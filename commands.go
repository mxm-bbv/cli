package main

import (
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
	"github.com/mxm-bbv/cli/internal/tripwire"
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
	ui.Println("\n" + ui.Recap(final.(ui.RunnerModel)))
	if final.(ui.RunnerModel).Failed {
		ui.Println(ui.StyleErr.Render("\n  Aborted with a failed step. Full log: " + logPath))
		return false
	}
	// What forge just changed is not an intrusion.
	if !system.DryRun && tripwire.Installed() {
		tripwire.Run(true)
	}
	return true
}

// runCaddy installs (or updates) the Caddy web server from the given repo,
// the one chosen at setup, or the default.
func runCaddy(args []string) int {
	if !requireRoot("caddy " + strings.Join(args, " ")) {
		return 1
	}
	cfg, ok := loadState()
	if len(args) > 0 {
		cfg.CaddyRepo = args[0]
	} else if cfg.CaddyRepo == "" {
		cfg.CaddyRepo = config.DefaultCaddyRepo
	}
	if err := config.ValidGitHubRepo(cfg.CaddyRepo); err != nil {
		ui.Println(ui.StyleErr.Render("  " + cfg.CaddyRepo + ": " + err.Error() + "\n  usage: sudo forge caddy [owner/repo]"))
		return 2
	}
	logPath := openLog(false)
	st, ctx := steps.CaddySteps(cfg)
	if !runSteps(st, ctx, logPath) {
		return 1
	}
	if ok {
		if saved, err := config.Load(config.StatePath); err == nil {
			saved.CaddyRepo = cfg.CaddyRepo
			_ = saveState(saved)
		}
	}
	ui.Println("\n" + ui.Report("Caddy is serving", ctx, logPath))
	return 0
}

// runSSH shows or changes whether SSH is reachable from the internet.
func runSSH(args []string) int {
	if !requireRoot("ssh " + strings.Join(args, " ")) {
		return 1
	}
	mode := ""
	if len(args) > 0 {
		mode = args[0]
	}
	switch mode {
	case "":
		if steps.SSHOpenToInternet() {
			ui.Println("  SSH: " + ui.StyleWarn.Render("open to the internet") +
				ui.StyleMuted.Render("  (only over Tailscale: sudo forge ssh tailnet-only)"))
		} else {
			ui.Println("  SSH: " + ui.StyleOK.Render("Tailscale only") +
				ui.StyleMuted.Render("  (reopen: sudo forge ssh public)"))
		}
		return 0

	case "tailnet-only":
		ip, err := steps.CheckTailnetOnly()
		if err != nil {
			ui.Println(ui.StyleErr.Render("  Not closing SSH: ") + err.Error())
			return 1
		}
		ok, err := ui.Confirm("Close SSH to the internet? Only Tailscale will reach it.",
			"The way back in if Tailscale ever fails: your provider's web console, then  sudo forge ssh public")
		if err != nil || !ok {
			ui.Println(ui.StyleMuted.Render("  Nothing changed."))
			return 0
		}
		if err := steps.SetSSHTailnetOnly(true); err != nil {
			ui.Println(ui.StyleErr.Render("  " + err.Error()))
			return 1
		}
		rememberSSHTailnetOnly(true)
		ui.Println(ui.StyleOK.Render("  SSH now answers only over Tailscale") + "  — " + ip +
			ui.StyleMuted.Render("\n  Keep this session open and check a new one before you log out."))
		return 0

	case "public":
		if err := steps.SetSSHTailnetOnly(false); err != nil {
			ui.Println(ui.StyleErr.Render("  " + err.Error()))
			return 1
		}
		rememberSSHTailnetOnly(false)
		ui.Println(ui.StyleOK.Render("  SSH is open to the internet again") + ui.StyleMuted.Render(" (key-only, fail2ban)"))
		return 0
	}
	ui.Println(ui.StyleErr.Render("  usage: sudo forge ssh [tailnet-only | public]"))
	return 2
}

// rememberSSHTailnetOnly records the choice, so a re-run of the setup keeps it.
func rememberSSHTailnetOnly(on bool) {
	if cfg, ok := loadState(); ok {
		cfg.SSHTailnetOnly = on
		_ = saveState(cfg)
	}
}

// runAgentSecret switches this box's Portainer Agent to the shared
// AGENT_SECRET (asked for hidden, never on the command line).
func runAgentSecret() int {
	if !requireRoot("agent-secret") {
		return 1
	}
	secret, err := ui.AskSecret("AGENT_SECRET of your Portainer Server")
	if err != nil {
		return 1
	}
	if secret == "" {
		ui.Println(ui.StyleMuted.Render("  Nothing changed."))
		return 0
	}
	if err := config.ValidAgentSecret(secret); err != nil {
		ui.Println(ui.StyleErr.Render("  AGENT_SECRET: " + err.Error()))
		return 2
	}
	cfg, _ := loadState()
	cfg.AgentSecret = secret
	cfg.InstallTailscale = true
	logPath := openLog(false)
	st, ctx := steps.TailscaleSteps(cfg)
	if !runSteps(st, ctx, logPath) {
		return 1
	}
	ui.Println("\n" + ui.Report("Portainer Agent uses the shared secret", ctx, logPath))
	return 0
}

// runTripwire is what the forge-tripwire timer runs every minute.
func runTripwire(args []string) int {
	if !requireRoot("tripwire") {
		return 1
	}
	switch {
	case len(args) == 0:
		return tripwire.Run(false)
	case args[0] == "--baseline":
		return tripwire.Run(true)
	case args[0] == "--show":
		tripwire.Show()
		return 0
	}
	ui.Println(ui.StyleErr.Render("  usage: sudo forge tripwire [--baseline | --show]"))
	return 2
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
