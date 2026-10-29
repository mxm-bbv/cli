package steps

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// Telegram alerts turn the box into something that tells you when it is in
// trouble — the missing "detection" half of the incident (malware ran for
// months at 100% CPU before anyone noticed). Everything here is push-only over
// HTTPS to api.telegram.org; nothing listens. What is worth a message, and how
// often, is decided in Go (internal/alerts, through `forge alert`): the shell
// scripts below only notice things.

const (
	forgeLibDir     = "/usr/local/lib/forge"
	forgeEtcDir     = "/etc/forge"
	alertsEnvPath   = "/etc/forge/alerts.env"
	notifyPath      = "/usr/local/lib/forge/notify.sh"
	healthPath      = "/usr/local/lib/forge/health-check.sh"
	auditNotifyPath = "/usr/local/lib/forge/audit-notify.sh"
	loginNotifyPath = "/usr/local/lib/forge/ssh-login-notify.sh"
	pamSSHDPath     = "/etc/pam.d/sshd"
	sshrcPath       = "/etc/ssh/sshrc" // pre-0.2 login hook, migrated away
)

func alertsStep() Step {
	return Step{
		Name: "Telegram alerts: daily audit, health & SSH-login pushes",
		Skip: func(c *Context) bool { return !c.Cfg.EnableAlerts },
		Run: func(c *Context) error {
			cfg := c.Cfg
			for _, d := range []string{forgeLibDir, forgeEtcDir, "/var/lib/forge"} {
				if _, err := system.Run("install", "-m", "0755", "-d", d); err != nil {
					return err
				}
			}

			// alerts.env is sourced by root-run shell scripts, so a value with
			// $(…) or a newline would execute as root. Only accept the shapes
			// Telegram actually issues.
			if err := config.ValidTelegramToken(cfg.TelegramBotToken); err != nil {
				return err
			}
			if err := config.ValidTelegramChatID(cfg.AlertsChatID); err != nil {
				return err
			}

			if err := config.ValidAlertName(cfg.AlertName); err != nil {
				return fmt.Errorf("the name in alerts: %w", err)
			}
			quiet, err := alerts.ParseQuiet(strings.Join(cfg.AlertQuietFrom, " "))
			if err != nil {
				return err
			}

			// Secret config, root-only. WriteFile logs the path, never the body,
			// so the bot token can't leak into the command log.
			if err := system.WriteFile(alertsEnvPath, alertsEnv(cfg, quiet), 0o600); err != nil {
				return err
			}

			// Resolve the absolute path of THIS forge binary so the scheduled
			// audit works regardless of PATH.
			self, err := os.Executable()
			if err != nil || self == "" {
				self = "/usr/local/bin/forge"
			}

			files := map[string]string{
				notifyPath:      notifyScript,
				healthPath:      withForge(healthScript, self),
				auditNotifyPath: withForge(auditNotifyScript, self),
				loginNotifyPath: withForge(loginNotifyScript, self),
			}
			for path, body := range files {
				if err := system.WriteFile(path, body, 0o755); err != nil {
					return err
				}
			}

			// systemd units + timers.
			units := map[string]string{
				"/etc/systemd/system/forge-health.service": healthUnit,
				"/etc/systemd/system/forge-health.timer":   healthTimer,
				"/etc/systemd/system/forge-audit.service":  auditUnit,
				"/etc/systemd/system/forge-audit.timer":    auditTimer,
			}
			for path, body := range units {
				if err := system.WriteFile(path, body, 0o644); err != nil {
					return err
				}
			}
			if _, err := system.Run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			for _, t := range []string{"forge-health.timer", "forge-audit.timer"} {
				if _, err := system.Run("systemctl", "enable", "--now", t); err != nil {
					return err
				}
			}

			// SSH-login alert via pam_exec (runs as root, so it can read the
			// root-only alerts.env — the old /etc/ssh/sshrc hook ran as the
			// logging-in user and never fired for non-root logins).
			if err := removeLegacySSHRC(); err != nil {
				return err
			}
			if cfg.LoginAlerts() != alerts.LoginsOff {
				if err := installPAMLoginHook(); err != nil {
					return err
				}
				if cfg.TailscaleSSH {
					c.Notes = append(c.Notes, "Tailscale SSH sessions bypass sshd/PAM — they don't trigger login alerts (see the Tailscale admin console's logs)")
				}
			}

			// Prove it end-to-end so a wrong token/chat-id surfaces now.
			said := loginsSaid(cfg.LoginAlerts(), len(quiet))
			if !system.DryRun {
				if err := alerts.Send(alerts.Alert{Text: "✅ forge: alerts are set. Here: the daily audit, health warnings, the tripwire, " + said + "."}); err != nil {
					c.Notes = append(c.Notes, "⚠ alerts installed but the Telegram test message failed — check the bot token and chat ID in "+alertsEnvPath)
					return nil
				}
			}
			c.Notes = append(c.Notes, "Telegram alerts active: daily audit, health checks every 15 min, "+said+"; more than "+fmt.Sprint(alerts.DefaultMaxPerHour)+" an hour wait for a daily summary. Sent a test message.")
			return nil
		},
	}
}

// AlertsSteps sets up (or changes) Telegram alerts on their own: the machine
// mode's alerts module.
func AlertsSteps(cfg config.Config) ([]Step, *Context) {
	cfg.EnableAlerts = true
	return []Step{alertsStep()}, &Context{Cfg: cfg}
}

// alertsEnv is /etc/forge/alerts.env. The shell scripts source it as root, so
// every value is a shape that can't run anything: the token and chat ID are
// checked against what Telegram issues, the name and the quiet list are single
// quoted and can't hold a quote.
func alertsEnv(cfg config.Config, quiet []netip.Prefix) string {
	nets := make([]string, len(quiet))
	for i, p := range quiet {
		nets[i] = p.String()
	}
	return fmt.Sprintf("TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\nALERT_NAME='%s'\nALERT_SSH_LOGIN=%s\nALERT_QUIET_FROM='%s'\nALERT_MAX_PER_HOUR=%d\nALERT_LOAD_PCT=%d\nALERT_DISK_PCT=%d\n",
		cfg.TelegramBotToken, cfg.AlertsChatID, cfg.AlertName, cfg.LoginAlerts(), strings.Join(nets, " "),
		alerts.DefaultMaxPerHour, cfg.AlertLoadPerCPU, cfg.AlertDiskPercent)
}

// loginsSaid tells what reaches the chat about SSH logins.
func loginsSaid(mode string, quiet int) string {
	said := map[string]string{
		alerts.LoginsNew: "a user's first SSH login from an address each day (the rest in a daily summary)",
		alerts.LoginsAll: "every SSH login",
		alerts.LoginsOff: "no SSH logins",
	}[mode]
	if quiet > 0 && mode != alerts.LoginsOff {
		said += fmt.Sprintf(", logins from %d quiet address(es) only in the summary", quiet)
	}
	return said
}

// withForge puts the absolute path of this forge binary into a script, so the
// scheduled checks work regardless of PATH.
func withForge(script, self string) string {
	return strings.ReplaceAll(script, "@FORGE@", self)
}

// tripwireStep schedules `forge tripwire` every minute. It runs last so its
// baseline is the finished server, not forge's own work in progress.
func tripwireStep() Step {
	return Step{
		Name: "Tripwire: alert on what intruders change",
		Skip: func(c *Context) bool { return !c.Cfg.EnableAlerts || !c.Cfg.Tripwire },
		Run: func(c *Context) error {
			self, err := os.Executable()
			if err != nil || self == "" {
				self = "/usr/local/bin/forge"
			}
			if err := system.WriteFile("/etc/systemd/system/forge-tripwire.service", fmt.Sprintf(tripwireUnit, self), 0o644); err != nil {
				return err
			}
			if err := system.WriteFile("/etc/systemd/system/forge-tripwire.timer", tripwireTimer, 0o644); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			// Baseline after the unit files exist, or they'd be the first alert.
			if _, err := system.Run(self, "tripwire", "--baseline"); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "enable", "--now", "forge-tripwire.timer"); err != nil {
				return err
			}
			c.Notes = append(c.Notes, "Tripwire armed: new SSH keys, users, sudo rights, open ports, services, cron jobs or SUID files reach Telegram within a minute (see the current state: sudo forge tripwire --show)")
			return nil
		},
	}
}

// pamLoginHookLine is appended to /etc/pam.d/sshd. "optional" means a missing
// or failing script can never affect authentication or the session — PAM
// ignores an optional module's result when required modules are present.
const pamLoginHookLine = "session optional pam_exec.so quiet " + loginNotifyPath

// installPAMLoginHook adds the forge login hook to sshd's PAM stack exactly
// once (forge's sshd policy sets UsePAM yes).
func installPAMLoginHook() error {
	const marker = "# forge-ssh-login-alert"
	if system.FileContains(pamSSHDPath, marker) {
		return nil
	}
	existing, err := readFileOrEmpty(pamSSHDPath)
	if err != nil {
		return err
	}
	if existing == "" && !system.DryRun {
		return fmt.Errorf("%s not found — is openssh-server installed?", pamSSHDPath)
	}
	if err := system.BackupFile(pamSSHDPath); err != nil {
		return err
	}
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return system.WriteFile(pamSSHDPath, existing+marker+"\n"+pamLoginHookLine+"\n", 0o644)
}

// removeLegacySSHRC strips the hook older forge versions put in
// /etc/ssh/sshrc (deleting the file if nothing else is left — its mere
// existence disables sshd's built-in xauth handling).
func removeLegacySSHRC() error {
	existing, err := readFileOrEmpty(sshrcPath)
	if err != nil || !strings.Contains(existing, legacySSHRCBlock) {
		return err
	}
	rest := strings.Replace(existing, legacySSHRCBlock, "", 1)
	if strings.TrimSpace(rest) == "" {
		return system.RemoveFile(sshrcPath)
	}
	return system.WriteFile(sshrcPath, rest, 0o644)
}

// The scripts below test alerts.env before sourcing it: in sh, "." of a missing
// file is a special-builtin error that aborts the script (exit 2), so the
// tempting ". file || exit 0" never reaches its "|| exit 0".

// notifyScript reads a message from $1 (or stdin) and pushes it to Telegram.
// --data-urlencode keeps arbitrary text safe — no JSON escaping, no injection.
// The bot token is part of the URL, so the URL goes to curl as a config file
// on stdin (`-K -`, fed by the printf builtin) instead of argv, which any local
// user could read from /proc while curl runs.
const notifyScript = `#!/bin/sh
# Managed by forge. Sends its argument (or stdin) to Telegram.
set -u
[ -r /etc/forge/alerts.env ] || exit 0
. /etc/forge/alerts.env
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] || exit 0
[ -n "${TELEGRAM_CHAT_ID:-}" ] || exit 0
if [ $# -gt 0 ]; then MSG="$1"; else MSG="$(cat)"; fi
printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_BOT_TOKEN" |
  curl -fsS --max-time 15 -X POST -K - \
    --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${MSG}" \
    -d disable_web_page_preview=true >/dev/null
`

// loginNotifyScript is run by pam_exec (as root) for every sshd session. It
// returns immediately — `forge alert login` runs in the background, so a slow
// network can never delay a login — and that decides whether the login is
// worth a message (PAM_USER and PAM_RHOST come in the environment).
const loginNotifyScript = `#!/bin/sh
# Managed by forge. Called by pam_exec from /etc/pam.d/sshd.
[ "${PAM_TYPE:-}" = "open_session" ] || exit 0
[ -r /etc/forge/alerts.env ] || exit 0
@FORGE@ alert login </dev/null >/dev/null 2>&1 &
exit 0
`

// healthScript warns on sustained load, disk pressure and pending reboots.
// `forge alert` keeps a standing condition from repeating (6 h for load and
// disk, a day for a reboot), and sends the daily summary of what it held back.
const healthScript = `#!/bin/sh
# Managed by forge. Host-health checks every 15 minutes.
set -u
[ -r /etc/forge/alerts.env ] || exit 0
. /etc/forge/alerts.env

CPUS=$(nproc 2>/dev/null || echo 1)
LOAD15=$(awk '{print $3}' /proc/loadavg)
PCT=$(awk -v l="$LOAD15" -v c="$CPUS" 'BEGIN{printf "%d",(l/c)*100}')
if [ "$PCT" -ge "${ALERT_LOAD_PCT:-90}" ]; then
  @FORGE@ alert send --key load --every 6h "⚠️ sustained load ${LOAD15} (${PCT}% of ${CPUS} CPUs) — check 'docker stats' / 'top'"
fi

DISK=$(df -P / | awk 'NR==2{gsub(/%/,"",$5);print $5}')
if [ "$DISK" -ge "${ALERT_DISK_PCT:-85}" ]; then
  @FORGE@ alert send --key disk --every 6h "⚠️ root filesystem ${DISK}% full"
fi

if [ -f /var/run/reboot-required ]; then
  @FORGE@ alert send --key reboot --every 24h "🔄 reboot required (security updates pending)"
fi

@FORGE@ alert digest
`

// auditNotifyScript runs `forge audit --quiet` and pushes only when it finds
// something.
const auditNotifyScript = `#!/bin/sh
# Managed by forge. Daily compromise/exposure sweep -> Telegram on findings.
set -u
OUT=$(@FORGE@ audit --quiet 2>/dev/null)
CODE=$?
[ "$CODE" -eq 0 ] && exit 0
@FORGE@ alert send --urgent --key audit --every 12h "🚨 forge audit found issues (severity $CODE):
$OUT"
`

// legacySSHRCBlock is the exact hook forge < 0.2 appended to /etc/ssh/sshrc.
const legacySSHRCBlock = `# forge-ssh-login-alert
if [ -r /etc/forge/alerts.env ] && [ -x /usr/local/lib/forge/notify.sh ]; then
  ( . /etc/forge/alerts.env 2>/dev/null
    [ "${ALERT_SSH_LOGIN:-0}" = "1" ] && \
      /usr/local/lib/forge/notify.sh "🔐 SSH login: ${USER:-?}@$(hostname) from ${SSH_CONNECTION%% *}" ) >/dev/null 2>&1 &
fi
`

const healthUnit = `[Unit]
Description=forge host-health checks (Telegram alerts)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/forge/health-check.sh
`

const healthTimer = `[Unit]
Description=Run forge health checks every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
`

const auditUnit = `[Unit]
Description=forge daily audit sweep (Telegram alerts)
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/lib/forge/audit-notify.sh
`

// tripwireUnit: %s is the forge binary. Low priority — it must never compete
// with the services it watches.
const tripwireUnit = `[Unit]
Description=forge tripwire (Telegram alert on persistence changes)
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s tripwire
Nice=10
IOSchedulingClass=idle
`

const tripwireTimer = `[Unit]
Description=Run forge tripwire every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
`

const auditTimer = `[Unit]
Description=Run forge audit once a day

[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
`
