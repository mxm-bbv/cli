package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
)

// RunForm presents the interactive wizard, mutating and returning cfg.
func RunForm(cfg config.Config, askPassword bool) (config.Config, error) {
	swap := strconv.Itoa(cfg.SwapGB)
	port := strconv.Itoa(cfg.SSHPort)
	pw, pw2 := "", ""
	src := string(cfg.AdminKeySource)
	pmode := string(cfg.PortainerAccess)
	repos := strings.Join(cfg.GitHubRepos, ", ")
	if !cfg.InstallPortainer {
		pmode = "off"
	}

	groups := []*huh.Group{
		huh.NewGroup(
			huh.NewNote().Title("Deploy user").
				Description("A non-root user with sudo + docker access for day-to-day deploys."),
			huh.NewInput().Title("Username").Value(&cfg.Username).
				Validate(steps.ValidUsername),
		),
	}

	if askPassword {
		groups = append(groups, huh.NewGroup(
			huh.NewInput().Title("Password for the deploy user").
				EchoMode(huh.EchoModePassword).Value(&pw).
				Validate(nonEmpty("password")),
			huh.NewInput().Title("Confirm password").
				EchoMode(huh.EchoModePassword).Value(&pw2).
				Validate(func(s string) error {
					if s != pw {
						return errors.New("passwords do not match")
					}
					return nil
				}),
		))
	}

	groups = append(groups,
		huh.NewGroup(
			huh.NewNote().Title("Your SSH access").
				Description("How should we install YOUR public key so you can log in as the deploy user?"),
			huh.NewSelect[string]().Title("Admin key source").Value(&src).
				Options(
					huh.NewOption("Fetch from github.com/<user>.keys", string(config.AdminKeyGitHub)),
					huh.NewOption("Paste the public key", string(config.AdminKeyPaste)),
					huh.NewOption("Read from a local file path", string(config.AdminKeyFile)),
					huh.NewOption("Skip (I'll set it up myself)", string(config.AdminKeySkip)),
				),
		),
		huh.NewGroup(
			huh.NewText().Title("Public key / file path / GitHub username").
				Description("Paste the key, or a path, or a GitHub username — matching the choice above.").
				Value(&cfg.AdminKeyValue),
		).WithHideFunc(func() bool { return src == string(config.AdminKeySkip) }),

		huh.NewGroup(
			huh.NewNote().Title("GitHub").
				Description("Private repos this server pulls from. forge creates a read-only deploy key\n"+
					"for each and registers it through GitHub — you approve once with a code.\n"+
					"Add more later:  sudo forge github owner/repo"),
			huh.NewInput().Title("Repos (owner/repo, comma-separated — blank to skip)").Value(&repos).
				Validate(func(s string) error {
					_, err := config.ParseGitHubRepos(s)
					return err
				}),
		),

		huh.NewGroup(
			huh.NewConfirm().Title("Apply base tuning (hostname, timezone, swap, utils)?").
				Value(&cfg.EnableBaseTuning),
			huh.NewInput().Title("Hostname (blank = leave as-is)").Value(&cfg.Hostname).
				Validate(config.ValidHostname),
			huh.NewInput().Title("Timezone").Value(&cfg.Timezone),
			huh.NewInput().Title("Swap size in GB (0 = none)").Value(&swap).
				Validate(intRange(0, 128)),
		),

		huh.NewGroup(
			huh.NewNote().Title("Tailscale").
				Description("A private network for admin access — Portainer and emergency SSH from your\n"+
					"phone, invisible to the internet. forge only installs it; log in whenever\n"+
					"you like:  sudo forge tailscale  (shows a QR code to scan)"),
			huh.NewConfirm().Title("Install Tailscale?").Value(&cfg.InstallTailscale),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Enable Tailscale SSH at login (emergency access from your phone)?").
				Value(&cfg.TailscaleSSH),
		).WithHideFunc(func() bool { return !cfg.InstallTailscale }),

		huh.NewGroup(
			huh.NewConfirm().Title("Docker daemon hardening + log rotation (daemon.json)?").Value(&cfg.EnableLogRotation),
			huh.NewSelect[string]().Title("Portainer Agent access").
				Description("An agent is root-equivalent. Published on 0.0.0.0:9001 it WILL be found and abused.").
				Options(
					huh.NewOption("Tailscale only — invisible to the internet (recommended)", "tailnet"),
					huh.NewOption("Public :9001 with AGENT_SECRET (NOT recommended)", "public"),
					huh.NewOption("Don't install Portainer Agent", "off"),
				).Value(&pmode).
				Validate(func(v string) error {
					if v == "tailnet" && !cfg.InstallTailscale {
						return errors.New("needs Tailscale — go back (shift+tab) and install it, or pick another option")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Install Watchtower (monitor-only update checks)?").Value(&cfg.InstallWatchtower),
			huh.NewConfirm().Title("Enable firewall (UFW + fail2ban + DOCKER-USER container rules)?").Value(&cfg.EnableFirewall),
			huh.NewConfirm().Title("Enable unattended security upgrades?").Value(&cfg.EnableAutoUpdates),
			huh.NewConfirm().Title("…and reboot at 04:00 when an update needs it (kernel fixes)?").Value(&cfg.AutoReboot),
			huh.NewConfirm().Title("Kernel & network hardening (sysctl: no ICMP redirects, no unprivileged BPF…)?").
				Value(&cfg.HardenKernel),
		),

		// Telegram alerts — the detection half: know when the box is in trouble.
		huh.NewGroup(
			huh.NewConfirm().Title("Send Telegram alerts (daily audit, health, SSH logins)?").
				Value(&cfg.EnableAlerts),
		),
		huh.NewGroup(
			huh.NewNote().Title("Telegram").
				Description("Create a bot with @BotFather, then get your chat ID from @userinfobot.\nThe bot token is a secret and is never written to your config file."),
			huh.NewInput().Title("Bot token").
				EchoMode(huh.EchoModePassword).Value(&cfg.TelegramBotToken).
				Validate(config.ValidTelegramToken),
			huh.NewInput().Title("Chat ID").Value(&cfg.AlertsChatID).
				Validate(config.ValidTelegramChatID),
			huh.NewConfirm().Title("Alert on every SSH login?").Value(&cfg.AlertOnSSHLogin),
		).WithHideFunc(func() bool { return !cfg.EnableAlerts }),

		// SSH hardening — the dangerous bits, asked explicitly.
		huh.NewGroup(
			huh.NewNote().Title("⚠  SSH hardening").
				Description("These run LAST. forge refuses to disable password auth unless a key is installed, and validates sshd -t before restart — so you can't lock yourself out.\n\nThis is the last page: submitting it starts the setup."),
			huh.NewInput().Title("SSH port").Value(&port).Validate(intRange(1, 65535)),
			huh.NewConfirm().Title("Disable root login over SSH?").Value(&cfg.DisableRootLogin),
			huh.NewConfirm().Title("Disable password authentication (key-only)?").Value(&cfg.DisablePassauth),
		),
	)

	if err := newForm(groups...).Run(); err != nil {
		return cfg, err
	}

	cfg.GitHubRepos, _ = config.ParseGitHubRepos(repos) // validated by the field
	cfg.AdminKeySource = config.AdminKeySource(src)
	cfg.SwapGB = atoiOr(swap, cfg.SwapGB)
	cfg.SSHPort = atoiOr(port, cfg.SSHPort)
	cfg.DeployPassword = pw
	cfg.InstallPortainer = pmode != "off"
	if cfg.InstallPortainer {
		cfg.PortainerAccess = config.PortainerAccess(pmode)
	}
	return cfg, nil
}

// AskSecret prompts for a single hidden value (used in --config replay for
// secrets that are never serialised, like the Tailscale auth key).
func AskSecret(title string) (string, error) {
	v := ""
	form := newForm(huh.NewGroup(
		huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&v),
	))
	if err := form.Run(); err != nil {
		return "", err
	}
	return v, nil
}

// AskPassword prompts only for the deploy user's password (used in --config
// replay, where the rest of the answers come from a file).
func AskPassword(username string) (string, error) {
	pw, pw2 := "", ""
	form := newForm(huh.NewGroup(
		huh.NewInput().Title("Password for "+username).
			EchoMode(huh.EchoModePassword).Value(&pw).Validate(nonEmpty("password")),
		huh.NewInput().Title("Confirm password").
			EchoMode(huh.EchoModePassword).Value(&pw2).
			Validate(func(s string) error {
				if s != pw {
					return errors.New("passwords do not match")
				}
				return nil
			}),
	))
	if err := form.Run(); err != nil {
		return "", err
	}
	return pw, nil
}

// newForm builds a themed form that fits the terminal. huh sizes every group
// to the tallest one, capped at the terminal height, but its view is one line
// taller than that (the blank line above the help) — so on a short terminal
// the top line, the focused field's title, scrolls out of sight. Reporting a
// terminal one line shorter keeps the whole view on screen.
func newForm(groups ...*huh.Group) *huh.Form {
	return huh.NewForm(groups...).
		WithTheme(forgeTheme()).
		WithProgramOptions(tea.WithFilter(fitHeight))
}

func fitHeight(_ tea.Model, msg tea.Msg) tea.Msg {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		ws.Height = max(ws.Height-1, 1)
		return ws
	}
	return msg
}

func nonEmpty(field string) func(string) error {
	return func(s string) error {
		if len(s) == 0 {
			return errors.New(field + " is required")
		}
		return nil
	}
}

func intRange(lo, hi int) func(string) error {
	return func(s string) error {
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return errors.New("must be a number")
		}
		if v < lo || v > hi {
			return fmt.Errorf("must be between %d and %d", lo, hi)
		}
		return nil
	}
}

func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

// forgeTheme tints huh's Charm theme with the ember palette, for dark and
// light terminals alike (huh detects which one it is running in).
func forgeTheme() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		t := huh.ThemeCharm(isDark)
		t.Focused.Title = t.Focused.Title.Foreground(ColorEmber).Bold(true)
		t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(ColorGold).Bold(true)
		t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(ColorEmber)
		t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(ColorEmber)
		t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(ColorEmber)
		t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(ColorEmber)
		t.Focused.FocusedButton = t.Focused.FocusedButton.Background(ColorEmber)
		t.Focused.Next = t.Focused.FocusedButton
		t.Blurred.Title = t.Blurred.Title.Foreground(ColorAsh)
		t.Group.Title = t.Focused.Title
		return t
	})
}
