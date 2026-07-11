package ui

import (
	"errors"
	"strconv"

	"github.com/charmbracelet/huh"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
)

// RunForm presents the interactive wizard, mutating and returning cfg. The
// deploy password is collected here and carried on cfg.DeployPassword (never
// serialised). askPassword=false skips password prompting (e.g. replay where
// the user is set up already) — but by default we always ask.
func RunForm(cfg config.Config, askPassword bool) (config.Config, error) {
	// String/int shims for huh inputs.
	swap := strconv.Itoa(cfg.SwapGB)
	port := strconv.Itoa(cfg.SSHPort)
	pw, pw2 := "", ""
	src := string(cfg.AdminKeySource)

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
		// Admin login key.
		huh.NewGroup(
			huh.NewNote().Title("Your SSH access").
				Description("How should we install YOUR public key so you can log in as the deploy user?"),
			huh.NewSelect[string]().Title("Admin key source").Value(&src).
				Options(
					huh.NewOption("Paste the public key", string(config.AdminKeyPaste)),
					huh.NewOption("Read from a local file path", string(config.AdminKeyFile)),
					huh.NewOption("Fetch from github.com/<user>.keys", string(config.AdminKeyGitHub)),
					huh.NewOption("Skip (I'll set it up myself)", string(config.AdminKeySkip)),
				),
		),
		huh.NewGroup(
			huh.NewText().Title("Public key / file path / GitHub username").
				Description("Paste the key, or a path, or a GitHub username — matching the choice above.").
				Value(&cfg.AdminKeyValue),
		).WithHideFunc(func() bool { return src == string(config.AdminKeySkip) }),

		// GitHub deploy key.
		huh.NewGroup(
			huh.NewConfirm().Title("Generate an ed25519 key for cloning private GitHub repos?").
				Value(&cfg.GenerateGitHubKey),
			huh.NewInput().Title("Key comment").Value(&cfg.GitHubKeyComment),
		),

		// Base tuning.
		huh.NewGroup(
			huh.NewConfirm().Title("Apply base tuning (hostname, timezone, swap, utils)?").
				Value(&cfg.EnableBaseTuning),
			huh.NewInput().Title("Hostname (blank = leave as-is)").Value(&cfg.Hostname),
			huh.NewInput().Title("Timezone").Value(&cfg.Timezone),
			huh.NewInput().Title("Swap size in GB (0 = none)").Value(&swap).
				Validate(isInt),
		),

		// Features.
		huh.NewGroup(
			huh.NewConfirm().Title("Docker log rotation (daemon.json)?").Value(&cfg.EnableLogRotation),
			huh.NewConfirm().Title("Install Portainer Agent (:9001)?").Value(&cfg.InstallPortainer),
			huh.NewConfirm().Title("Install Watchtower (auto-update containers)?").Value(&cfg.InstallWatchtower),
			huh.NewConfirm().Title("Enable UFW firewall + fail2ban?").Value(&cfg.EnableFirewall),
			huh.NewConfirm().Title("Enable unattended security upgrades?").Value(&cfg.EnableAutoUpdates),
		),

		// SSH hardening — the dangerous bits, asked explicitly.
		huh.NewGroup(
			huh.NewNote().Title("⚠  SSH hardening").
				Description("These can lock you out if your key isn't working. They run LAST, after sshd -t validation."),
			huh.NewInput().Title("SSH port").Value(&port).Validate(isInt),
			huh.NewConfirm().Title("Disable root login over SSH?").Value(&cfg.DisableRootLogin),
			huh.NewConfirm().Title("Disable password authentication (key-only)?").Value(&cfg.DisablePassauth),
		),
	)

	form := huh.NewForm(groups...).WithTheme(forgeTheme())
	if err := form.Run(); err != nil {
		return cfg, err
	}

	// Commit shims back into the typed config.
	cfg.AdminKeySource = config.AdminKeySource(src)
	cfg.SwapGB = atoiOr(swap, cfg.SwapGB)
	cfg.SSHPort = atoiOr(port, cfg.SSHPort)
	cfg.DeployPassword = pw
	return cfg, nil
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

func isInt(s string) error {
	if _, err := strconv.Atoi(s); err != nil {
		return errors.New("must be a number")
	}
	return nil
}

func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
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
