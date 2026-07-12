// Package steps defines the ordered, idempotent provisioning steps.
package steps

import "github.com/mxm-bbv/cli/internal/config"

// Context carries the config plus artifacts produced during a run (surfaced in
// the final summary).
type Context struct {
	Cfg               config.Config
	GitHubPubKey      string // populated by the ssh step when a key is generated
	AdminKeyInstalled bool   // true once a valid authorized_keys exists for the deploy user
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
		portainerStep(),
		watchtowerStep(),
		firewallStep(),
		fail2banStep(),
		autoUpdatesStep(),
		sshHardeningStep(), // last: closes root / password login
	}
	return steps, c
}

func always(*Context) bool { return false }
