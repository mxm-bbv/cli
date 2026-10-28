// Command forge — ServerForge: a TUI wizard that turns a clean Ubuntu/Debian
// box (or a derivative such as Linux Mint) into a production-ready host (Docker, Portainer Agent, deploy user, SSH
// keys and hardening) in a single pass.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mxm-bbv/cli/internal/audit"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/lint"
	"github.com/mxm-bbv/cli/internal/status"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
	"github.com/mxm-bbv/cli/internal/ui"
	"github.com/mxm-bbv/cli/internal/update"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	// Subcommands are dispatched before flag parsing so they can take their own
	// arguments. The wizard is the default when no subcommand is given.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "audit":
			quiet := len(os.Args) > 2 && (os.Args[2] == "--quiet" || os.Args[2] == "-q")
			os.Exit(audit.Run(quiet))
		case "status":
			os.Exit(status.Run())
		case "lint":
			if len(os.Args) < 3 {
				ui.Println(ui.StyleErr.Render("  usage: forge lint <docker-compose.yml>"))
				os.Exit(2)
			}
			os.Exit(lint.Run(os.Args[2]))
		case "tailscale":
			os.Exit(runTailscale())
		case "github":
			os.Exit(runGitHub(os.Args[2:]))
		case "update":
			if len(os.Args) > 2 && os.Args[2] == "images" {
				os.Exit(update.Images())
			}
			allowUnsigned := false
			for _, a := range os.Args[2:] {
				if a == "--allow-unsigned" {
					allowUnsigned = true
				}
			}
			os.Exit(update.SelfUpdate(allowUnsigned))
		}
	}

	var (
		dryRun   = flag.Bool("dry-run", false, "print the actions without changing anything")
		cfgPath  = flag.String("config", "", "load wizard answers from a YAML file (non-interactive)")
		savePath = flag.String("save-config", "", "save the wizard answers to a YAML file")
		_        = flag.Bool("yes", false, "no-op, kept for older scripts (there is no final prompt)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		ui.Printf("forge %s\n", version)
		return
	}

	system.DryRun = *dryRun

	// Full transcript of every command → a log file, so nothing is hidden and a
	// failed run can be diagnosed after the fact.
	logPath := openLog(*dryRun)

	ui.Print(ui.Banner(version))

	// Privilege & OS checks — before the wizard, so nobody fills it in on a
	// box forge can't provision.
	plat, platErr := system.DetectPlatform(system.ReadOSRelease())
	if !*dryRun {
		if !system.IsRoot() {
			ui.Println(ui.StyleErr.Render("  This must run as root. Try:  sudo forge"))
			os.Exit(1)
		}
		if platErr != nil {
			ui.Println(ui.StyleErr.Render("  " + platErr.Error()))
			os.Exit(1)
		}
		if !system.HasSystemd() {
			ui.Println(ui.StyleErr.Render("  systemd is not running — forge needs it to manage services, timers and sshd."))
			os.Exit(1)
		}
	} else if !system.IsRoot() {
		ui.Println(ui.StyleWarn.Render("  [dry-run] not root — that's fine, nothing will be executed.\n"))
	}
	if platErr == nil {
		ui.Println(ui.StyleMuted.Render("  Detected: " + plat.String()))
		if note := plat.SupportNote(); note != "" {
			ui.Println(ui.StyleWarn.Render("  ⚠ " + note))
		}
		ui.Println()
	} else {
		ui.Println(ui.StyleWarn.Render("  [dry-run] " + platErr.Error() + "\n"))
	}

	// Gather configuration: either replay a file or run the full wizard.
	cfg, err := gatherConfig(*cfgPath)
	if err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		os.Exit(1)
	}

	if *savePath != "" {
		if err := config.Save(cfg, *savePath); err != nil {
			ui.Println(ui.StyleErr.Render("  could not save config: " + err.Error()))
			os.Exit(1)
		}
		ui.Println(ui.StyleOK.Render("  Saved answers to " + *savePath + " (password excluded)\n"))
	}

	// Unattended Tailscale login (CI, image builds): Tailscale's usual env var.
	cfg.TailscaleAuthKey = os.Getenv("TS_AUTHKEY")

	// Keep the answers for `forge tailscale` / `forge github` later on.
	if !*dryRun {
		if err := saveState(cfg); err != nil {
			ui.Println(ui.StyleWarn.Render("  could not save " + config.StatePath + ": " + err.Error()))
		}
	}

	// Execute.
	st, ctx := steps.BuildSteps(cfg)
	if !runSteps(st, ctx, logPath) {
		os.Exit(1)
	}

	ui.Println("\n" + ui.Summary(ctx, *dryRun, logPath))

	if *dryRun {
		ui.Println(ui.StyleMuted.Render(fmt.Sprintf("  [dry-run] %d commands would have run.", len(system.CommandLog))))
	}
}

// openLog creates the transcript file and wires it into the system package.
// Best-effort: if it can't be created, we carry on without a log.
func openLog(dryRun bool) string {
	if dryRun {
		return ""
	}
	dir := "/var/log"
	if !system.IsRoot() {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "forge.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return ""
	}
	system.LogWriter = f
	return path
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
		if cfg.EnableAlerts {
			tok, err := ui.AskSecret("Telegram bot token")
			if err != nil {
				return cfg, err
			}
			if err := config.ValidTelegramToken(tok); err != nil {
				return cfg, err
			}
			cfg.TelegramBotToken = tok
		}
		return cfg, nil
	}
	cfg, err := ui.RunForm(config.Default(), true)
	if err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}
