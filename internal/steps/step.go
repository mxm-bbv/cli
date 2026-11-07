// Package steps defines the ordered, idempotent provisioning steps.
package steps

import (
	"fmt"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// Context carries the config plus artifacts produced during a run (surfaced in
// the final summary).
type Context struct {
	Cfg               config.Config
	Platform          system.Platform // detected by preflight (upstream family/codename)
	Container         string          // container type when running in LXC/OpenVZ/…, else ""
	GitHubPubKey      string          // populated by the ssh step when a key is generated
	AdminKeyInstalled bool            // true once a valid authorized_keys exists for the deploy user
	TailnetIP         string          // populated by the tailscale step
	AgentSecret       string          // AGENT_SECRET for pairing the Portainer Agent (shown once)
	AgentDeferred     bool            // tailnet agent waits for `forge tailscale`
	AgentSecretNew    bool            // AgentSecret was generated here — the Portainer Server needs it
	TailscaleLogin    bool            // log in to Tailscale now (browser/QR) instead of leaving it for later
	GitHubRepos       []string        // repos whose deploy key works (ssh -T verified)
	Notes             []string
	Result            map[string]any // what a machine-mode module hands back to the program (forge run's done event)
}

// Step is a single, idempotent unit of work.
type Step struct {
	Name string
	// Skip reports whether the step is unnecessary (already done or disabled).
	Skip func(c *Context) bool
	// Run performs the work.
	Run func(c *Context) error
}

// BuildSteps assembles the ordered step list for the given config and returns
// it together with the shared Context. SSH hardening is intentionally last so
// the box stays reachable until everything else succeeded.
func BuildSteps(cfg config.Config) ([]Step, *Context) {
	// A tailnet-only agent needs the tailnet address, so its setup logs in to
	// Tailscale on the spot (QR code) — the agent is up when setup ends.
	c := &Context{Cfg: cfg, TailscaleLogin: tailnetAgent(cfg)}
	steps := []Step{
		preflightStep(),
		baseStep(),
		dockerStep(),
		logRotationStep(),
		userStep(),
		sshKeysStep(),
		githubStep(),    // deploy keys via the GitHub API, approved once with a code
		tailscaleStep(), // before portainer: the agent binds to the tailnet IP
		portainerStep(),
		watchtowerStep(),
		caddyStep(), // web server on :80/:443 (your caddy repo)
		firewallStep(),
		fail2banStep(),
		dockerUserFirewallStep(), // containers must respect the firewall too
		sysctlStep(),
		autoUpdatesStep(),
		alertsStep(),       // detection: Telegram push for audit/health/logins
		sshHardeningStep(), // closes root / password login
		tripwireStep(),     // last: its baseline is the finished server
	}
	return steps, c
}

// ServerSteps is BuildSteps for a program driving the setup over ssh: everything
// but closing sshd, and Tailscale's login when it's asked for. The program signs
// in as the deploy user first, on a connection of its own, and only then closes
// the door with SSHLoginSteps: nobody is locked out by a key that doesn't work.
func ServerSteps(cfg config.Config, tailscaleLogin bool) ([]Step, *Context) {
	all, c := BuildSteps(cfg)
	c.TailscaleLogin = c.TailscaleLogin || tailscaleLogin
	st := make([]Step, 0, len(all))
	for _, s := range all {
		if s.Name != sshHardeningName {
			st = append(st, s)
		}
	}
	return st, c
}

// SSHLoginSteps applies forge's sshd policy with root and password sign-in as
// cfg says. It always runs: opening them again is as much a change as closing
// them. Closing root (or passwords) refuses while the deploy user has no key.
func SSHLoginSteps(cfg config.Config) ([]Step, *Context) {
	s := sshHardeningStep()
	s.Skip = nil
	run := s.Run
	s.Run = func(c *Context) error {
		if c.Cfg.DisableRootLogin && !system.DryRun && !hasAuthorizedKey(c.Cfg.HomeDir()+"/.ssh/authorized_keys") {
			return fmt.Errorf("refusing to close root login: %s has no SSH key, nobody could sign in", c.Cfg.Username)
		}
		return run(c)
	}
	return []Step{s}, &Context{Cfg: cfg, AdminKeyInstalled: hasAuthorizedKey(cfg.HomeDir() + "/.ssh/authorized_keys")}
}

// CurrentSSHPort is the port sshd answers on now (22 when it can't tell).
func CurrentSSHPort() int {
	if ports := currentSSHPorts(); len(ports) > 0 {
		return ports[0]
	}
	return 22
}

// ProjectsFolderStep makes the folder the deploy user keeps its projects in
// and gives it that user. Only the folder itself: what's in it stays whose it is.
func ProjectsFolderStep(user, folder string) Step {
	return Step{
		Name: "Projects folder " + folder + " for " + user,
		Run: func(*Context) error {
			_, err := system.Run("install", "-d", "-o", user, "-g", user, folder)
			return err
		},
	}
}

// TailscaleSteps logs the box in to Tailscale (link + QR code in the runner)
// and then starts what waited for the tailnet: the Portainer Agent in tailnet
// mode. Re-running it is harmless.
func TailscaleSteps(cfg config.Config) ([]Step, *Context) {
	c := &Context{Cfg: cfg, TailscaleLogin: true}
	agent := portainerStep()
	agent.Skip = func(c *Context) bool { return !tailnetAgent(c.Cfg) }
	return []Step{tailscaleStep(), agent}, c
}

// CaddySteps installs the caddy repo (with a deploy key if it is private).
func CaddySteps(cfg config.Config) ([]Step, *Context) {
	cfg.GitHubRepos = nil
	return []Step{githubStep(), caddyStep()}, &Context{Cfg: cfg}
}

// GitHubSteps gives cfg.Username read-only deploy keys for cfg.GitHubRepos.
func GitHubSteps(cfg config.Config) ([]Step, *Context) {
	return []Step{githubStep()}, &Context{Cfg: cfg}
}

func always(*Context) bool { return false }

// platform returns the detected platform, detecting it on demand when a step
// runs without preflight (tests, a skipped preflight).
func (c *Context) platform() (system.Platform, error) {
	if c.Platform.Family != "" {
		return c.Platform, nil
	}
	p, err := system.DetectPlatform(hostOSRelease())
	if err == nil {
		c.Platform = p
	}
	return p, err
}
