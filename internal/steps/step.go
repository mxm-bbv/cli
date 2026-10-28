// Package steps defines the ordered, idempotent provisioning steps.
package steps

import (
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
	TailscaleLogin    bool            // log in to Tailscale now (browser/QR) instead of leaving it for later
	GitHubRepos       []string        // repos whose deploy key works (ssh -T verified)
	Notes             []string
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
	c := &Context{Cfg: cfg}
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
