package main

import (
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
	"github.com/mxm-bbv/cli/internal/ui"
)

// runSteps drives steps in the live runner and reports whether they all
// succeeded (a failure has been reported to the operator already).
func runSteps(st []steps.Step, ctx *steps.Context, logPath string) bool {
	final, err := tea.NewProgram(ui.NewRunner(st, ctx, logPath)).Run()
	// An abort leaves the current step's goroutine behind: stop a login it may
	// still be waiting on, and drop its temporary credentials.
	system.StopWaiting()
	steps.Cleanup()
	if err != nil {
		ui.Println(ui.StyleErr.Render("  runner error: " + err.Error()))
		return false
	}
	if final.(ui.RunnerModel).Failed {
		ui.Println(ui.StyleErr.Render("\n  Aborted with a failed step. Full log: " + logPath))
		return false
	}
	return true
}

// saveState records the wizard's answers (no secrets) at config.StatePath.
func saveState(cfg config.Config) error {
	if err := os.MkdirAll(filepath.Dir(config.StatePath), 0o700); err != nil {
		return err
	}
	return config.Save(cfg, config.StatePath)
}

// loadState returns the answers of the provisioning run, or ok=false when
// this box was not set up by forge.
func loadState() (cfg config.Config, ok bool) {
	cfg, err := config.Load(config.StatePath)
	if err != nil {
		return config.Default(), false
	}
	return cfg, true
}

// requireRoot prints the usual hint and reports whether we are root.
func requireRoot(cmd string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	ui.Println(ui.StyleErr.Render("  This must run as root. Try:  sudo forge " + cmd))
	return false
}

// runTailscale logs the box in to Tailscale — the runner shows the login link
// as a QR code — and then starts what waited for the tailnet: the Portainer
// Agent, when the setup chose tailnet mode.
func runTailscale() int {
	if !requireRoot("tailscale") {
		return 1
	}
	cfg, ok := loadState()
	if !ok {
		// Not a forge-provisioned box: just log in, start nothing.
		cfg.InstallPortainer = false
	}
	cfg.InstallTailscale = true
	cfg.TailscaleAuthKey = os.Getenv("TS_AUTHKEY")

	logPath := openLog(false)
	st, ctx := steps.TailscaleSteps(cfg)
	if !runSteps(st, ctx, logPath) {
		return 1
	}
	ui.Println("\n" + ui.Report("Tailscale connected", ctx, logPath))
	return 0
}

// runGitHub gives the deploy user read-only deploy keys for the given repos
// (owner/repo or GitHub URLs) and remembers them for later runs.
func runGitHub(args []string) int {
	repos, err := config.ParseGitHubRepos(strings.Join(args, " "))
	if err != nil || len(repos) == 0 {
		msg := "usage: sudo forge github owner/repo [owner/repo …]"
		if err != nil {
			msg = err.Error() + "\n  " + msg
		}
		ui.Println(ui.StyleErr.Render("  " + msg))
		return 2
	}
	if !requireRoot("github " + strings.Join(args, " ")) {
		return 1
	}
	cfg, ok := loadState()
	cfg.GitHubRepos = repos

	logPath := openLog(false)
	st, ctx := steps.GitHubSteps(cfg)
	if !runSteps(st, ctx, logPath) {
		return 1
	}
	if ok {
		if saved, err := config.Load(config.StatePath); err == nil {
			saved.GitHubRepos, _ = config.ParseGitHubRepos(strings.Join(append(saved.GitHubRepos, repos...), " "))
			_ = saveState(saved)
		}
	}
	ui.Println("\n" + ui.Report("GitHub deploy keys ready", ctx, logPath))
	return 0
}
