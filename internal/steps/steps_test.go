package steps

import (
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

func TestDryRunAllSteps(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)

	cfg := config.Default()
	cfg.Hostname = "web-01"
	cfg.SSHPort = 2222
	cfg.AdminKeySource = config.AdminKeyPaste
	cfg.AdminKeyValue = "ssh-ed25519 AAAAC3NzaC1lZDI1 admin@laptop"
	cfg.InstallWatchtower = true
	cfg.DeployPassword = "s3cret"
	cfg.TailscaleAuthKey = "tskey-auth-TESTONLY"
	cfg.EnableAlerts = true
	cfg.AlertsChatID = "123456"
	cfg.TelegramBotToken = "123456789:TESTONLY_secret_token_value_abcdefgh"
	cfg.GitHubRepos = []string{"mxm-bbv/app"}

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
		"apt-get -o DPkg::Lock::Timeout=300 update",               // preflight (non-interactive)
		"linux/ubuntu/dists/noble/Release",                        // docker repo availability checked first
		"sources.list.d/docker.list",                              // docker apt source (always written)
		"ca-certificates curl gnupg sudo openssh-client iproute2", // sudo: minimal Debian lacks it
		"--force-confold dbus",                                    // hostnamectl/timedatectl need a bus
		"fail2ban python3-systemd",                                // journald backend needs python3-systemd
		"useradd -m -s /bin/bash deploy",                          // deploy user
		"usermod -aG sudo deploy",                                 // sudo group
		"usermod -aG docker deploy",                               // docker group
		"ssh-keygen -q -t ed25519 -C deploy@",                     // one deploy key per repo
		"-f /home/deploy/.ssh/github-mxm-bbv--app -N",             // …named after the repo
		"append -> /home/deploy/.ssh/config",                      // ssh alias that selects the key
		"url.git@github-mxm-bbv--app:mxm-bbv/app.git.insteadOf git@github.com:mxm-bbv/app.git", // plain clone URLs use it
		"gh auth login --web (one-time code)",                                                  // device login, approved on a phone
		"gh repo deploy-key add /home/deploy/.ssh/github-mxm-bbv--app.pub --repo mxm-bbv/app",  // read-only by default
		"gh auth logout",                              // the login is thrown away
		"tailscale up --auth-key=<hidden> --ssh",      // tailnet join (key redacted)
		"<tailnet-ip>:9001:9001",                      // agent bound to the tailnet, not 0.0.0.0
		"-e AGENT_SECRET",                             // agent pairing secret (value via env)
		portainerAgentImage,                           // portainer (pinned version)
		watchtowerImage,                               // watchtower (pinned version)
		"--monitor-only",                              // watchtower never auto-replaces containers
		"no-new-privileges",                           // containers hardened
		"ufw allow 2222/tcp",                          // firewall honours ssh port
		"ufw allow in on tailscale0",                  // tailnet is a trusted admin interface
		"ufw allow 22/tcp",                            // current SSH port stays open until sshd moves
		"jail.d/sshd.local",                           // fail2ban jail
		"fail2ban-client -t",                          // jail validated before restart
		"forge-docker-user.service",                   // DOCKER-USER rules (docker can't bypass UFW)
		"forge-audit.timer",                           // scheduled audit -> Telegram
		"forge-health.timer",                          // scheduled health checks
		"alerts.env",                                  // secret alert config written
		"20auto-upgrades",                             // unattended-upgrades config
		"sysctl -q -e -p /etc/sysctl.d/90-forge.conf", // kernel & network hardening
		"journald.conf.d/90-forge.conf",               // journal capped on a small disk
		"apt.conf.d/52forge-auto-reboot",              // kernel fixes take effect
		"needrestart/conf.d/90-forge.conf",            // outdated services restarted
		"sshd -t",                                     // sshd validated before restart
		"sshd -T (verify effective settings)",         // effective config checked (drop-in overrides)
		"systemctl restart ssh",                       // sshd restarted last
		"connect 127.0.0.1:2222, expect SSH banner",   // new port verified before closing the old one
		"ufw delete allow 22/tcp",                     // transitional SSH rule removed
		"pam.d/sshd",                                  // SSH-login alerts via pam_exec
		"ssh-login-notify.sh",                         // login hook script
		"tripwire --baseline",                         // tripwire baseline = the finished server
		"forge-tripwire.timer",                        // checked every minute
		"/home/deploy/.ssh/github-mr-studio-kz-ua--caddy-core.pub --repo MR-Studio-KZ-UA/caddy-core", // private caddy repo gets a deploy key
		"git clone --quiet git@github.com:MR-Studio-KZ-UA/caddy-core.git /home/deploy/caddy-core",    // …and is cloned with it
		"write /home/deploy/caddy-core/.env",                                        // PROJECTS_PATH
		"-f /home/deploy/caddy-core/docker-compose.prod.yml up -d --remove-orphans", // the web server runs
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
	if strings.Contains(log, "TESTONLY_secret_token") {
		t.Fatal("telegram bot token leaked into command log")
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
	dryRunAs(t, ubuntuNoble, false)

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
	prev := system.DryRun
	system.DryRun = false
	t.Cleanup(func() { system.DryRun = prev })

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
	dryRunAs(t, ubuntuNoble, false)

	cfg := config.Default()
	cfg.EnableFirewall = false
	cfg.InstallPortainer = false
	cfg.InstallTailscale = false
	cfg.InstallWatchtower = false
	cfg.EnableAutoUpdates = false
	cfg.EnableAlerts = false
	cfg.HardenKernel = false
	cfg.CaddyRepo = ""

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
		"Telegram alerts: daily audit, health & SSH-login pushes",
		"Kernel & network hardening (sysctl)",
		"GitHub: read-only deploy keys for your repos",
		"Tripwire: alert on what intruders change",
		"Caddy web server (your caddy repo)",
	} {
		if !skipped[name] {
			t.Errorf("expected step %q to be skipped when its feature is disabled", name)
		}
	}
}
