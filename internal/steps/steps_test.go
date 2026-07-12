package steps

import (
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

func TestDryRunAllSteps(t *testing.T) {
	system.DryRun = true
	system.CommandLog = nil
	t.Cleanup(func() { system.DryRun = false; system.CommandLog = nil })

	cfg := config.Default()
	cfg.Hostname = "web-01"
	cfg.SSHPort = 2222
	cfg.AdminKeySource = config.AdminKeyPaste
	cfg.AdminKeyValue = "ssh-ed25519 AAAAC3NzaC1lZDI1 admin@laptop"
	cfg.InstallWatchtower = true
	cfg.DeployPassword = "s3cret"

	st, ctx := BuildSteps(cfg)
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			continue
		}
		if err := s.Run(ctx); err != nil {
			t.Fatalf("step %q failed: %v", s.Name, err)
		}
	}

	log := strings.Join(system.CommandLog, "\n")
	wantSubstrings := []string{
		"apt-get -o DPkg::Lock::Timeout=300 update",
		"sources.list.d/docker.list",
		"useradd -m -s /bin/bash deploy",
		"usermod -aG sudo deploy",
		"usermod -aG docker deploy",
		"ssh-keygen -t ed25519",
		portainerAgentImage,
		watchtowerImage,
		"no-new-privileges",
		"ufw allow 2222/tcp",
		"jail.d/sshd.local",
		"20auto-upgrades",
		"sshd -t",
		"systemctl restart ssh",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(log, want) {
			t.Errorf("expected command log to contain %q\n--- log ---\n%s", want, log)
		}
	}

	if strings.Contains(log, "s3cret") {
		t.Fatal("deploy password leaked into command log")
	}
}

func TestValidUsernameRejectsInjection(t *testing.T) {
	good := []string{"deploy", "web_01", "ci-runner", "_svc"}
	for _, n := range good {
		if err := ValidUsername(n); err != nil {
			t.Errorf("expected %q to be valid: %v", n, err)
		}
	}
	bad := []string{
		"", "Deploy", "1user", "a b", "a;rm -rf /", "a$(id)", "a`whoami`",
		"a/b", "../root", "user\nname", "toolongusernameaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, n := range bad {
		if err := ValidUsername(n); err == nil {
			t.Errorf("expected %q to be rejected", n)
		}
	}
}

func TestGitHubUsernameValidation(t *testing.T) {
	for _, n := range []string{"torvalds", "mxm-bbv", "a"} {
		if !githubUserRe.MatchString(n) {
			t.Errorf("expected %q to be a valid github username", n)
		}
	}
	for _, n := range []string{"", "-bad", "a b", "a;b", "a/b", "a$b"} {
		if githubUserRe.MatchString(n) {
			t.Errorf("expected %q to be rejected", n)
		}
	}
}

func TestLockoutGuard(t *testing.T) {
	system.DryRun = false
	t.Cleanup(func() { system.DryRun = true })

	cfg := config.Default()
	cfg.Username = "nonexistent_user_xyz"
	cfg.DisablePassauth = true
	c := &Context{Cfg: cfg, AdminKeyInstalled: false}

	err := sshHardeningStep().Run(c)
	if err == nil || !strings.Contains(err.Error(), "locked out") {
		t.Fatalf("expected lockout guard to refuse, got: %v", err)
	}
}

func TestSkipDisabledFeatures(t *testing.T) {
	system.DryRun = true
	t.Cleanup(func() { system.DryRun = false })

	cfg := config.Default()
	cfg.EnableFirewall = false
	cfg.InstallPortainer = false
	cfg.InstallWatchtower = false
	cfg.EnableAutoUpdates = false

	st, ctx := BuildSteps(cfg)
	skipped := map[string]bool{}
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			skipped[s.Name] = true
		}
	}
	for _, name := range []string{
		"UFW firewall: allow SSH/HTTP/HTTPS, enable",
		"Portainer Agent (port 9001)",
		"Watchtower (auto-update containers)",
		"Unattended security upgrades",
	} {
		if !skipped[name] {
			t.Errorf("expected step %q to be skipped when its feature is disabled", name)
		}
	}
}
