// Command forge — ServerForge: a TUI wizard that turns a clean Ubuntu/Debian
// box (or a derivative such as Linux Mint) into a production-ready host (Docker, Portainer Agent, deploy user, SSH
// keys and hardening) in a single pass.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	ui.Brand = "forge " + version
	// Subcommands are dispatched before flag parsing so they can take their own
	// arguments. The wizard is the default when no subcommand is given.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "audit":
			if len(os.Args) > 2 && os.Args[2] == "--json" {
				os.Exit(audit.RunJSON())
			}
			quiet := len(os.Args) > 2 && (os.Args[2] == "--quiet" || os.Args[2] == "-q")
			os.Exit(audit.Run(quiet))
		case "status":
			if len(os.Args) > 2 && os.Args[2] == "--json" {
				os.Exit(status.RunJSON(version))
			}
			os.Exit(status.Run())
		case "alert":
			os.Exit(runAlert(os.Args[2:]))
		case "modules":
			os.Exit(runModules(os.Args[2:]))
		case "run":
			os.Exit(runModule(os.Args[2:]))
		case "machine":
			os.Exit(runMachineAccess(os.Args[2:]))
		case "lint":
			if len(os.Args) < 3 {
				ui.Println(ui.StyleErr.Render("  usage: forge lint <docker-compose.yml>"))
				os.Exit(2)
			}
			os.Exit(lint.Run(os.Args[2]))
		case "caddy":
			os.Exit(runCaddy(os.Args[2:]))
		case "ssh":
			os.Exit(runSSH(os.Args[2:]))
		case "agent-secret":
			os.Exit(runAgentSecret(os.Args[2:]))
		case "agent-remove":
			os.Exit(runAgentRemove(os.Args[2:]))
		case "rotate-agents":
			os.Exit(runRotateAgents(os.Args[2:]))
		case "tripwire":
			os.Exit(runTripwire(os.Args[2:]))
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
	// A word forge doesn't know (a typo, or a command from a newer version)
	// must never fall through to the full setup.
	if flag.NArg() > 0 {
		ui.Println(ui.StyleErr.Render("  unknown command: "+flag.Arg(0)) + "\n\n" + usage)
		os.Exit(2)
	}

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
		ui.Platform = plat.String()
		ui.Println(ui.StyleMuted.Render("  Detected: " + plat.String()))
		if note := plat.SupportNote(); note != "" {
			ui.Println(ui.StyleWarn.Render("  ⚠ " + note))
		}
		ui.Println()
	} else {
		ui.Println(ui.StyleWarn.Render("  [dry-run] " + platErr.Error() + "\n"))
	}

	// The setup is for a fresh box. On one that already serves things and
	// was never set up by forge, say what it would touch and ask first.
	if *cfgPath == "" && !*dryRun {
		if _, provisioned := loadState(); !provisioned {
			if n := runningContainers(); n > 0 {
				ok, err := ui.Confirm(fmt.Sprintf("This server already runs %d containers. Run the full setup on it?", n),
					"The setup is meant for a fresh server: it changes SSH, the firewall, users and Docker's config.\n"+
						"For an existing one you probably want a single command instead:\n"+
						"  sudo forge agent-secret   Portainer Agent on Tailscale with your shared secret\n"+
						"  sudo forge tailscale      log in to Tailscale\n"+
						"  sudo forge audit          read-only security check")
				if err != nil || !ok {
					ui.Println(ui.StyleMuted.Render("  Nothing changed.") + "\n\n" + usage)
					return
				}
			}
		}
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
	if s := os.Getenv("PORTAINER_AGENT_SECRET"); s != "" && cfg.AgentSecret == "" {
		cfg.AgentSecret = s
	}

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
	// A re-run starts from the previous answers (and keeps choices made
	// later, like `forge ssh tailnet-only`).
	prev, _ := loadState()
	cfg, err := ui.RunForm(prev, true)
	if err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

// runningContainers counts running Docker containers (0 without Docker).
func runningContainers() int {
	out, err := system.Output("docker", "ps", "-q")
	if err != nil || out == "" {
		return 0
	}
	return len(strings.Split(out, "\n"))
}

const usage = `  forge                      set up a fresh server (wizard)
  sudo forge tailscale       log in to Tailscale, start the Portainer Agent on it
  sudo forge agent-secret    switch the Portainer Agent to your shared AGENT_SECRET
  sudo forge agent-remove    take the Portainer Agent off this server (containers managed over SSH instead)
  forge rotate-agents [--portainer DIR] [user@host …]
                             red button: new AGENT_SECRET on every server + your Portainer
  sudo forge github o/r …    read-only deploy keys for GitHub repos
  sudo forge caddy [o/r]     install/update the Caddy web server
  sudo forge ssh [tailnet-only|public]
  sudo forge tripwire [--show|--baseline]
  sudo forge audit | status | update [images] | lint <compose.yml>

  For programs (deploy.me over ssh): forge modules --json, sudo forge run <module>
  (inputs as JSON on stdin), status --json, audit --json; sudo forge machine enable
  lets the deploy user run them without a password.`
