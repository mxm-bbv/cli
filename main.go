// Command forge — ServerForge: a TUI wizard that turns a clean Ubuntu/Debian
// box into a production-ready host (Docker, Portainer Agent, deploy user, SSH
// keys and hardening) in a single pass.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mxm-bbv/cli/internal/audit"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
	"github.com/mxm-bbv/cli/internal/ui"
)

const version = "0.1.0"

func main() {
	// Subcommands (before flag parsing): `forge audit` — read-only IOC and
	// exposure scan of this host.
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		os.Exit(audit.Run())
	}

	var (
		dryRun    = flag.Bool("dry-run", false, "print the actions without changing anything")
		cfgPath   = flag.String("config", "", "load wizard answers from a YAML file (non-interactive)")
		savePath  = flag.String("save-config", "", "save the wizard answers to a YAML file")
		assumeYes = flag.Bool("yes", false, "skip the final confirmation prompt")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("forge %s\n", version)
		return
	}

	system.DryRun = *dryRun

	fmt.Print(ui.Banner(version))

	// Privilege & OS checks.
	if !*dryRun {
		if !system.IsRoot() {
			fmt.Println(ui.StyleErr.Render("  This must run as root. Try:  sudo forge"))
			os.Exit(1)
		}
		if rel := system.ReadOSRelease(); !rel.IsDebianLike() {
			fmt.Println(ui.StyleErr.Render("  Unsupported OS: " + rel.Pretty + " (Ubuntu/Debian only)"))
			os.Exit(1)
		}
	} else if !system.IsRoot() {
		fmt.Println(ui.StyleWarn.Render("  [dry-run] not root — that's fine, nothing will be executed.\n"))
	}

	// Gather configuration: either replay a file or run the full wizard.
	cfg, err := gatherConfig(*cfgPath)
	if err != nil {
		fmt.Println(ui.StyleErr.Render("  " + err.Error()))
		os.Exit(1)
	}

	if *savePath != "" {
		if err := config.Save(cfg, *savePath); err != nil {
			fmt.Println(ui.StyleErr.Render("  could not save config: " + err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.StyleOK.Render("  Saved answers to " + *savePath + " (password excluded)\n"))
	}

	// Final confirmation.
	if !*assumeYes {
		ok, err := ui.Confirm(confirmTitle(cfg, *dryRun))
		if err != nil || !ok {
			fmt.Println(ui.StyleMuted.Render("  Aborted."))
			return
		}
	}

	// Execute.
	st, ctx := steps.BuildSteps(cfg)
	model := ui.NewRunner(st, ctx)
	prog := tea.NewProgram(model)
	final, err := prog.Run()
	if err != nil {
		fmt.Println(ui.StyleErr.Render("  runner error: " + err.Error()))
		os.Exit(1)
	}

	rm := final.(ui.RunnerModel)
	if rm.Failed {
		fmt.Println(ui.StyleErr.Render("\n  A step failed — see the error above. Nothing further was applied."))
		os.Exit(1)
	}

	fmt.Println("\n" + ui.Summary(ctx, *dryRun))

	if *dryRun {
		fmt.Println(ui.StyleMuted.Render(fmt.Sprintf("  [dry-run] %d commands would have run.", len(system.CommandLog))))
	}
}

// gatherConfig either loads a YAML config (prompting only for the password) or
// runs the full interactive wizard.
func gatherConfig(cfgPath string) (config.Config, error) {
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return cfg, fmt.Errorf("load config: %w", err)
		}
		pw, err := ui.AskPassword(cfg.Username)
		if err != nil {
			return cfg, err
		}
		cfg.DeployPassword = pw
		// Secrets are never serialised — the tailnet auth key is re-prompted.
		if cfg.InstallPortainer && cfg.PortainerAccess == config.PortainerTailnet {
			key, err := ui.AskSecret("Tailscale auth key (empty if this box already joined)")
			if err != nil {
				return cfg, err
			}
			cfg.TailscaleAuthKey = key
		}
		return cfg, nil
	}
	return ui.RunForm(config.Default(), true)
}

func confirmTitle(cfg config.Config, dryRun bool) string {
	if dryRun {
		return "Show the plan for a dry run? (no changes will be made)"
	}
	return fmt.Sprintf("Provision this server now as user %q?", cfg.Username)
}
