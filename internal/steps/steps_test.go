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
		"apt-get -o DPkg::Lock::Timeout=300 update", // preflight (non-interactive apt)
		"sources.list.d/docker.list",                // docker apt source (always written)
		"useradd -m -s /bin/bash deploy",            // deploy user
		"usermod -aG sudo deploy",                   // sudo group
		"usermod -aG docker deploy",                 // docker group
		"ssh-keygen -t ed25519",                     // github key
		portainerAgentImage,                         // portainer (pinned version)
		watchtowerImage,                             // watchtower (pinned version)
		"no-new-privileges",                         // containers hardened
		"ufw allow 2222/tcp",                        // firewall honours ssh port
		"jail.d/sshd.local",                         // fail2ban jail
		"20auto-upgrades",                           // unattended-upgrades config
		"sshd -t",                                   // sshd validated before restart
		"systemctl restart ssh",                     // sshd restarted last
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(log, want) {
			t.Errorf("expected command log to contain %q\n--- log ---\n%s", want, log)
		}
	}

	// The deploy password must never appear in the command log.
	if strings.Contains(log, "s3cret") {
		t.Fatal("deploy password leaked into command log")
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
		"Portainer Agent (port 9001)",
		"Watchtower (auto-update containers)",
		"Unattended security upgrades",
	} {
		if !skipped[name] {
			t.Errorf("expected step %q to be skipped when its feature is disabled", name)
		}
	}
}
