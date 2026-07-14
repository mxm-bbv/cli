package steps

import (
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// TestDryRunAllSteps exercises every step in dry-run mode with all features
// enabled, asserting that the engine runs clean and emits the expected
// commands. This verifies the provisioning logic without needing a real host.
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
	cfg.TailscaleAuthKey = "tskey-auth-TESTONLY"

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
	// Assert on deterministic commands only — package installs and keyring
	// downloads are idempotent and may be skipped on an already-provisioned
	// host (like this CI box), which is correct behaviour.
	wantSubstrings := []string{
		"apt-get update",                         // preflight
		"sources.list.d/docker.list",             // docker apt source (always written)
		"useradd -m -s /bin/bash deploy",         // deploy user
		"usermod -aG sudo deploy",                // sudo group
		"usermod -aG docker deploy",              // docker group
		"ssh-keygen -t ed25519",                  // github key
		"tailscale up --auth-key=<hidden> --ssh", // tailnet join (key redacted)
		"<tailnet-ip>:9001:9001",                 // agent bound to the tailnet, not 0.0.0.0
		"-e AGENT_SECRET",                        // agent pairing secret (value via env)
		portainerAgentImage,                      // portainer (pinned version)
		watchtowerImage,                          // watchtower (pinned version)
		"--monitor-only",                         // watchtower never auto-replaces containers
		"no-new-privileges",                      // containers hardened
		"ufw allow 2222/tcp",                     // firewall honours ssh port
		"ufw allow in on tailscale0",             // tailnet is a trusted admin interface
		"jail.d/sshd.local",                      // fail2ban jail
		"forge-docker-user.service",              // DOCKER-USER rules (docker can't bypass UFW)
		"20auto-upgrades",                        // unattended-upgrades config
		"sshd -t",                                // sshd validated before restart
		"systemctl restart ssh",                  // sshd restarted last
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(log, want) {
			t.Errorf("expected command log to contain %q\n--- log ---\n%s", want, log)
		}
	}

	// Secrets must never appear in the command log.
	if strings.Contains(log, "s3cret") {
		t.Fatal("deploy password leaked into command log")
	}
	if strings.Contains(log, "tskey-auth-TESTONLY") {
		t.Fatal("tailscale auth key leaked into command log")
	}
	if ctx.AgentSecret == "" {
		t.Fatal("expected an AGENT_SECRET to be generated")
	}
	if strings.Contains(log, ctx.AgentSecret) {
		t.Fatal("AGENT_SECRET leaked into command log")
	}
}

// TestPortainerPublicMode covers the discouraged fallback: the agent stays on
// 0.0.0.0 but must carry a secret, skip tailscale, and open 9001 in DOCKER-USER.
func TestPortainerPublicMode(t *testing.T) {
	system.DryRun = true
	system.CommandLog = nil
	t.Cleanup(func() { system.DryRun = false; system.CommandLog = nil })

	cfg := config.Default()
	cfg.PortainerAccess = config.PortainerPublic
	cfg.AdminKeySource = config.AdminKeySkip
	cfg.GenerateGitHubKey = false

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
	if !strings.Contains(log, "-p 9001:9001") {
		t.Errorf("expected public binding, log:\n%s", log)
	}
	if strings.Contains(log, "tailscale up") {
		t.Error("tailscale must not run in public mode")
	}
	if !strings.Contains(log, "-e AGENT_SECRET") {
		t.Error("public agent must still require AGENT_SECRET")
	}
	if strings.Contains(log, "<tailnet-ip>") {
		t.Error("no tailnet binding expected in public mode")
	}
}

// TestValidUsernameRejectsInjection ensures crafted usernames can't slip into
// the shell commands that reference them.
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

// TestGitHubUsernameValidation guards the admin-key GitHub fetch path.
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

// TestSkipDisabledFeatures verifies that disabling features skips their steps.
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
		"Container firewall: DOCKER-USER rules (docker can't bypass UFW)",
		"Tailscale: private network for admin access",
		"Portainer Agent",
		"Watchtower (monitor-only update checks)",
		"Unattended security upgrades",
	} {
		if !skipped[name] {
			t.Errorf("expected step %q to be skipped when its feature is disabled", name)
		}
	}
}
