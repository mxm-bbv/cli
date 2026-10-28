package ui

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"

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
	installCaddy, caddyRepo := cfg.CaddyRepo != "", cmp.Or(cfg.CaddyRepo, config.DefaultCaddyRepo)
	if !cfg.InstallPortainer {
		pmode = "off"
	}

	pages := []page{{
		title: "Deploy user",
		fields: []huh.Field{
			huh.NewNote().Description("A non-root user with sudo + docker access for day-to-day deploys."),
			huh.NewInput().Title("Username").Value(&cfg.Username).Validate(steps.ValidUsername),
		},
	}}
	if askPassword {
		pages = append(pages, page{
			title: "Deploy user's password",
			fields: []huh.Field{
				huh.NewInput().Title("Password").
					EchoMode(huh.EchoModePassword).Value(&pw).Validate(nonEmpty("password")),
				huh.NewInput().Title("Confirm password").
					EchoMode(huh.EchoModePassword).Value(&pw2).Validate(samePassword(&pw)),
			},
		})
	}

	pages = append(pages,
		page{
			title: "Your SSH key",
			fields: []huh.Field{
				huh.NewNote().Description("How should forge install YOUR public key, so you can log in as the deploy user?"),
				huh.NewSelect[string]().Title("Key source").Value(&src).
					Options(
						huh.NewOption("Fetch from github.com/<user>.keys", string(config.AdminKeyGitHub)),
						huh.NewOption("Paste the public key", string(config.AdminKeyPaste)),
						huh.NewOption("Read from a local file path", string(config.AdminKeyFile)),
						huh.NewOption("Skip (I'll set it up myself)", string(config.AdminKeySkip)),
					),
			},
		},
		page{
			title: "Your SSH key",
			fields: []huh.Field{
				huh.NewText().Title("Public key / file path / GitHub username").
					Description("Matching the choice on the previous page.").
					Value(&cfg.AdminKeyValue),
			},
			hide: func() bool { return src == string(config.AdminKeySkip) },
		},
		page{
			title: "GitHub repos",
			fields: []huh.Field{
				huh.NewNote().Description("Private repos this server pulls from. Each gets its own read-only deploy key,\n" +
					"registered through GitHub — you approve once with a code on your phone.\n" +
					"More later:  sudo forge github owner/repo"),
				huh.NewInput().Title("Repos (owner/repo, comma-separated — blank to skip)").Value(&repos).
					Validate(func(s string) error {
						_, err := config.ParseGitHubRepos(s)
						return err
					}),
			},
		},
		page{
			title: "Base system",
			fields: []huh.Field{
				huh.NewConfirm().Title("Apply base tuning (hostname, timezone, swap, utils)?").Value(&cfg.EnableBaseTuning),
				huh.NewInput().Title("Hostname (blank = leave as-is)").Value(&cfg.Hostname).Validate(config.ValidHostname),
				huh.NewInput().Title("Timezone").Value(&cfg.Timezone),
				huh.NewInput().Title("Swap size in GB (0 = none)").Value(&swap).Validate(intRange(0, 128)),
			},
		},
		page{
			title: "Tailscale",
			fields: []huh.Field{
				huh.NewNote().Description("A private network for admin access — Portainer and emergency SSH from your\n" +
					"phone, invisible to the internet. forge only installs it; log in whenever\n" +
					"you like:  sudo forge tailscale  (shows a QR code to scan)"),
				huh.NewConfirm().Title("Install Tailscale?").Value(&cfg.InstallTailscale),
			},
		},
		page{
			title: "Tailscale",
			fields: []huh.Field{
				huh.NewConfirm().Title("Enable Tailscale SSH at login (emergency access from your phone)?").
					Value(&cfg.TailscaleSSH),
			},
			hide: func() bool { return !cfg.InstallTailscale },
		},
		page{
			title: "Docker & Portainer",
			fields: []huh.Field{
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
			},
		},
		page{
			title: "Web server",
			fields: []huh.Field{
				huh.NewNote().Description("Your Caddy setup as the server's web server on :80/:443 — cloned from GitHub\n" +
					"(a private repo gets a read-only deploy key), started with docker compose.\n" +
					"Later:  sudo forge caddy"),
				huh.NewConfirm().Title("Install your Caddy web server?").Value(&installCaddy),
			},
		},
		page{
			title: "Web server",
			fields: []huh.Field{
				huh.NewInput().Title("Caddy repo (owner/repo with a docker-compose.prod.yml)").Value(&caddyRepo).
					Validate(config.ValidGitHubRepo),
			},
			hide: func() bool { return !installCaddy },
		},
		page{
			title: "Maintenance & hardening",
			fields: []huh.Field{
				huh.NewConfirm().Title("Install Watchtower (monitor-only update checks)?").Value(&cfg.InstallWatchtower),
				huh.NewConfirm().Title("Enable firewall (UFW + fail2ban + DOCKER-USER container rules)?").Value(&cfg.EnableFirewall),
				huh.NewConfirm().Title("Enable unattended security upgrades?").Value(&cfg.EnableAutoUpdates),
				huh.NewConfirm().Title("…and reboot at 04:00 when an update needs it (kernel fixes)?").Value(&cfg.AutoReboot),
				huh.NewConfirm().Title("Kernel & network hardening (sysctl: no ICMP redirects, no unprivileged BPF…)?").
					Value(&cfg.HardenKernel),
			},
		},
		// Telegram alerts — the detection half: know when the box is in trouble.
		page{
			title: "Alerts",
			fields: []huh.Field{
				huh.NewConfirm().Title("Send Telegram alerts (daily audit, health, SSH logins, tripwire)?").
					Value(&cfg.EnableAlerts),
			},
		},
		page{
			title: "Telegram",
			fields: []huh.Field{
				huh.NewNote().Description("Create a bot with @BotFather, then get your chat ID from @userinfobot.\n" +
					"The bot token is a secret and is never written to your config file."),
				huh.NewInput().Title("Bot token").
					EchoMode(huh.EchoModePassword).Value(&cfg.TelegramBotToken).Validate(config.ValidTelegramToken),
				huh.NewInput().Title("Chat ID").Value(&cfg.AlertsChatID).Validate(config.ValidTelegramChatID),
				huh.NewConfirm().Title("Alert on every SSH login?").Value(&cfg.AlertOnSSHLogin),
				huh.NewConfirm().Title("Tripwire: alert within a minute on what intruders change?").
					Description("New SSH keys, users, sudo rights, open ports, services, cron jobs, SUID files…").
					Value(&cfg.Tripwire),
			},
			hide: func() bool { return !cfg.EnableAlerts },
		},
		// SSH hardening — the dangerous bits, asked explicitly.
		page{
			title: "⚠  SSH hardening",
			fields: []huh.Field{
				huh.NewNote().Description("These run LAST. forge refuses to disable password auth unless a key is installed,\n" +
					"and validates sshd -t before restart — so you can't lock yourself out.\n\n" +
					"This is the last page: submitting it starts the setup."),
				huh.NewInput().Title("SSH port").Value(&port).Validate(intRange(1, 65535)),
				huh.NewConfirm().Title("Disable root login over SSH?").Value(&cfg.DisableRootLogin),
				huh.NewConfirm().Title("Disable password authentication (key-only)?").Value(&cfg.DisablePassauth),
			},
		},
	)

	if err := runPages(pages...); err != nil {
		return cfg, err
	}

	cfg.GitHubRepos, _ = config.ParseGitHubRepos(repos) // validated by the field
	cfg.CaddyRepo = ""
	if installCaddy {
		cfg.CaddyRepo = caddyRepo
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
// secrets that are never serialised, like the Telegram bot token).
func AskSecret(title string) (string, error) {
	v := ""
	err := runPages(page{title: title, fields: []huh.Field{
		huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&v),
	}})
	return v, err
}

// AskPassword prompts only for the deploy user's password (used in --config
// replay, where the rest of the answers come from a file).
func AskPassword(username string) (string, error) {
	pw, pw2 := "", ""
	err := runPages(page{title: "Password for " + username, fields: []huh.Field{
		huh.NewInput().Title("Password").
			EchoMode(huh.EchoModePassword).Value(&pw).Validate(nonEmpty("password")),
		huh.NewInput().Title("Confirm password").
			EchoMode(huh.EchoModePassword).Value(&pw2).Validate(samePassword(&pw)),
	}})
	return pw, err
}

// Confirm shows a yes/no prompt (default: no).
func Confirm(title, description string) (bool, error) {
	ok := false
	err := runPages(page{title: title, fields: []huh.Field{
		huh.NewNote().Description(description),
		huh.NewConfirm().Title(title).Value(&ok),
	}})
	return ok, err
}

func samePassword(pw *string) func(string) error {
	return func(s string) error {
		if s != *pw {
			return errors.New("passwords do not match")
		}
		return nil
	}
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
