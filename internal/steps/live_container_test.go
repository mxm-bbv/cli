package steps

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// TestLiveInContainer runs real provisioning steps against a distro's actual
// apt repos, OpenSSH and fail2ban. It mutates the system, so it only runs as
// root inside a throwaway Docker container with FORGE_LIVE=1:
//
//	CGO_ENABLED=0 go test -c -o steps.test ./internal/steps
//	docker run --rm -e FORGE_LIVE=1 -v $PWD/steps.test:/steps.test:ro ubuntu:24.04 \
//	  /steps.test -test.run Live -test.v
//
// systemd isn't running in the container, so systemctl is shimmed; everything
// else (apt, curl, gpg fingerprint checks, dockerd --validate, sshd -t/-T,
// fail2ban-client -t) is the real thing.
func TestLiveInContainer(t *testing.T) {
	if os.Getenv("FORGE_LIVE") != "1" || os.Geteuid() != 0 || !system.FileExists("/.dockerenv") {
		t.Skip("set FORGE_LIVE=1 and run as root inside a disposable Docker container")
	}
	system.DryRun = false
	system.CommandLog = nil
	shim := "#!/bin/sh\necho \"$0 $*\" >> /tmp/shim.log\nexit 0\n"
	for _, bin := range []string{"systemctl", "timedatectl", "hostnamectl"} {
		if err := os.WriteFile("/usr/local/bin/"+bin, []byte(shim), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// openssh-server's postinst calls the real systemctl when it believes
	// systemd is running — install it before faking sd_booted below.
	for _, args := range [][]string{{"update", "-y"}, {"install", "-y", "--no-install-recommends", "openssh-server"}} {
		if _, err := aptGet(args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll("/run/systemd/system", 0o755); err != nil { // pretend sd_booted
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.SSHPort = 2222
	c := &Context{Cfg: cfg}

	run := func(t *testing.T, name string, fn func() error) {
		t.Helper()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	run(t, "preflight", func() error { return preflightStep().Run(c) })
	t.Logf("platform: %s (support %d)", c.Platform, c.Platform.Support)
	for _, bin := range []string{"sudo", "curl", "gpg", "ss", "ssh-keygen"} {
		if !system.CommandExists(bin) {
			t.Errorf("preflight should have installed %s", bin)
		}
	}

	run(t, "docker", func() error { return dockerStep().Run(c) })
	if out, err := system.Output("docker", "--version"); err != nil {
		t.Errorf("docker CLI missing after install: %v", err)
	} else {
		t.Log(out)
	}
	run(t, "daemon.json", func() error { return logRotationStep().Run(c) })

	run(t, "tailscale repo", func() error { return installTailscale(c.Platform) })

	run(t, "fail2ban", func() error { return fail2banStep().Run(c) })

	run(t, "time sync", ensureTimeSync)

	t.Run("sshd drop-in beats cloud-init", func(t *testing.T) {
		if _, err := system.Run("ssh-keygen", "-A"); err != nil {
			t.Fatal(err)
		}
		// A typical cloud image: cloud-init re-enables passwords, and the
		// provider's main config pins Port 22 explicitly.
		if err := os.WriteFile("/etc/ssh/sshd_config.d/50-cloud-init.conf", []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		main, err := os.ReadFile(sshdConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		pristine := strings.Replace(string(main), "#Port 22", "Port 22", 1)
		if err := os.WriteFile(sshdConfigPath, []byte(pristine), 0o644); err != nil {
			t.Fatal(err)
		}

		// The pre-0.2 approach — values in the main file — loses to cloud-init.
		legacy := pristine
		for _, o := range sshdOptions(cfg) {
			legacy = setSSHDOption(legacy, o.key, o.value)
		}
		if err := os.WriteFile(sshdConfigPath, []byte(legacy), 0o644); err != nil {
			t.Fatal(err)
		}
		ensureSSHDRuntimeDir()
		out, err := system.Output("sshd", "-T")
		if err != nil {
			t.Fatalf("sshd -T: %v", err)
		}
		if bad := sshdMismatches(parseSSHDT(out), cfg); len(bad) == 0 {
			t.Log("note: main-file edits were not overridden on this distro")
		} else {
			t.Logf("main-file approach is overridden, as expected: %v", bad)
		}
		if err := os.WriteFile(sshdConfigPath, []byte(pristine), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(sshdConfigPath + ".bak")

		// forge's approach.
		if _, err := applySSHDConfig(cfg); err != nil {
			t.Fatalf("applySSHDConfig: %v", err)
		}
		if err := verifyEffectiveSSHD(cfg); err != nil {
			t.Fatalf("effective config: %v", err)
		}
		out, _ = system.Output("sshd", "-T")
		eff := parseSSHDT(out)
		t.Logf("sshd -T → port %v, passwordauthentication %v, permitrootlogin %v, allowusers %v",
			eff["port"], eff["passwordauthentication"], eff["permitrootlogin"], eff["allowusers"])
	})

	t.Run("pam_exec login hook", func(t *testing.T) {
		run(t, "pam hook", installPAMLoginHook)
		if !system.FileContains(pamSSHDPath, pamLoginHookLine) {
			t.Fatal("hook line not in /etc/pam.d/sshd")
		}
		mods, _ := filepath.Glob("/usr/lib/*/security/pam_exec.so")
		mods2, _ := filepath.Glob("/lib/*/security/pam_exec.so")
		if len(mods)+len(mods2) == 0 {
			t.Error("pam_exec.so not found — the optional hook would be a no-op")
		}
		run(t, "again (idempotent)", installPAMLoginHook)
		if data, _ := os.ReadFile(pamSSHDPath); strings.Count(string(data), pamLoginHookLine) != 1 {
			t.Error("hook added twice")
		}
		// The hook must exit 0 immediately even with no alerts configured.
		if err := os.MkdirAll(forgeLibDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(loginNotifyPath, []byte(withForge(loginNotifyScript, "/bin/true")), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(loginNotifyPath)
		cmd.Env = append(os.Environ(), "PAM_TYPE=open_session", "PAM_USER=deploy", "PAM_RHOST=203.0.113.7")
		if err := cmd.Run(); err != nil {
			t.Errorf("login hook failed: %v", err)
		}
	})
}
