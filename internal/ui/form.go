package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

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
			huh.NewConfirm().Title("Generate an ed25519 key for cloning private GitHub repos?").
				Value(&cfg.GenerateGitHubKey),
			huh.NewInput().Title("Key comment").Value(&cfg.GitHubKeyComment),
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
			huh.NewConfirm().Title("Docker daemon hardening + log rotation (daemon.json)?").Value(&cfg.EnableLogRotation),
			huh.NewSelect[string]().Title("Portainer Agent access").
				Description("An agent is root-equivalent. Published on 0.0.0.0:9001 it WILL be found and abused.").
				Options(
					huh.NewOption("Tailscale only — invisible to the internet (recommended)", "tailnet"),
					huh.NewOption("Public :9001 with AGENT_SECRET (NOT recommended)", "public"),
					huh.NewOption("Don't install Portainer Agent", "off"),
				).Value(&pmode),
			huh.NewConfirm().Title("Install Watchtower (monitor-only update checks)?").Value(&cfg.InstallWatchtower),
			huh.NewConfirm().Title("Enable firewall (UFW + fail2ban + DOCKER-USER container rules)?").Value(&cfg.EnableFirewall),
			huh.NewConfirm().Title("Enable unattended security upgrades?").Value(&cfg.EnableAutoUpdates),
		),

		// Tailscale details — only when the agent rides the tailnet.
		huh.NewGroup(
			huh.NewNote().Title("Tailscale").
				Description("Create an auth key at https://login.tailscale.com/admin/settings/keys\nand install the Tailscale app on your laptop/phone to reach the agent."),
			huh.NewInput().Title("Tailscale auth key (empty if this box already joined)").
				EchoMode(huh.EchoModePassword).Value(&cfg.TailscaleAuthKey),
			huh.NewConfirm().Title("Enable Tailscale SSH (emergency access from your phone)?").
				Value(&cfg.TailscaleSSH),
		).WithHideFunc(func() bool { return pmode != "tailnet" }),

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
				Description("These run LAST. forge refuses to disable password auth unless a key is installed, and validates sshd -t before restart — so you can't lock yourself out."),
			huh.NewInput().Title("SSH port").Value(&port).Validate(intRange(1, 65535)),
			huh.NewConfirm().Title("Disable root login over SSH?").Value(&cfg.DisableRootLogin),
			huh.NewConfirm().Title("Disable password authentication (key-only)?").Value(&cfg.DisablePassauth),
		),
	)

	form := huh.NewForm(groups...).WithTheme(forgeTheme())
	if err := form.Run(); err != nil {
		return cfg, err
	}

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
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&v),
	)).WithTheme(forgeTheme())
	if err := form.Run(); err != nil {
		return "", err
	}
	return v, nil
}

// AskPassword prompts only for the deploy user's password (used in --config
// replay, where the rest of the answers come from a file).
func AskPassword(username string) (string, error) {
	pw, pw2 := "", ""
	form := huh.NewForm(huh.NewGroup(
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
	)).WithTheme(forgeTheme())
	if err := form.Run(); err != nil {
		return "", err
	}
	return pw, nil
}

// Confirm shows a yes/no prompt with the given title.
func Confirm(title string) (bool, error) {
	ok := false
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title(title).Value(&ok),
	)).WithTheme(forgeTheme())
	if err := form.Run(); err != nil {
		return false, err
	}
	return ok, nil
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

// forgeTheme tints the huh form with the ember palette.
func forgeTheme() *huh.Theme {
	t := huh.ThemeCharm()
	t.Focused.Title = t.Focused.Title.Foreground(ColorEmber).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(ColorGold).Bold(true)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(ColorEmber)
	return t
}
