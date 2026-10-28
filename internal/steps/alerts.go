package steps

import (
	"fmt"
	"os"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// Telegram alerts turn the box into something that tells you when it is in
// trouble — the missing "detection" half of the incident (malware ran for
// months at 100% CPU before anyone noticed). Everything here is push-only over
// HTTPS to api.telegram.org; nothing listens.

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

			// Secret config, root-only. WriteFile logs the path, never the body,
			// so the bot token can't leak into the command log.
			sshLogin := "0"
			if cfg.AlertOnSSHLogin {
				sshLogin = "1"
			}
			env := fmt.Sprintf(
				"TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\nALERT_SSH_LOGIN=%s\nALERT_LOAD_PCT=%d\nALERT_DISK_PCT=%d\n",
				cfg.TelegramBotToken, cfg.AlertsChatID, sshLogin, cfg.AlertLoadPerCPU, cfg.AlertDiskPercent,
			)
			if err := system.WriteFile(alertsEnvPath, env, 0o600); err != nil {
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
				healthPath:      healthScript,
				auditNotifyPath: fmt.Sprintf(auditNotifyScript, self),
				loginNotifyPath: loginNotifyScript,
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
			if cfg.AlertOnSSHLogin {
				if err := installPAMLoginHook(); err != nil {
					return err
				}
				if cfg.TailscaleSSH {
					c.Notes = append(c.Notes, "Tailscale SSH sessions bypass sshd/PAM — they don't trigger login alerts (see the Tailscale admin console's logs)")
				}
			}

			// Prove it end-to-end so a wrong token/chat-id surfaces now.
			if !system.DryRun {
				if _, err := system.Run("sh", notifyPath,
					"✅ forge: alerts configured on "+system.Hostname()+". You'll get a daily audit summary, health warnings and SSH-login notices here."); err != nil {
					c.Notes = append(c.Notes, "⚠ alerts installed but the Telegram test message failed — check the bot token and chat ID in "+alertsEnvPath)
					return nil
				}
			}
			c.Notes = append(c.Notes, "Telegram alerts active: daily audit, health checks every 15 min, SSH-login notices. Sent a test message.")
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
// returns immediately — the notification is sent in the background so a slow
// network can never delay a login.
const loginNotifyScript = `#!/bin/sh
# Managed by forge. Called by pam_exec from /etc/pam.d/sshd.
[ "${PAM_TYPE:-}" = "open_session" ] || exit 0
[ -r /etc/forge/alerts.env ] || exit 0
. /etc/forge/alerts.env
[ "${ALERT_SSH_LOGIN:-0}" = "1" ] || exit 0
/usr/local/lib/forge/notify.sh "🔐 SSH login: ${PAM_USER:-?}@$(hostname) from ${PAM_RHOST:-?}" </dev/null >/dev/null 2>&1 &
exit 0
`

// healthScript warns on sustained load, disk pressure and pending reboots,
// each rate-limited by a state file so a standing condition alerts once, not
// every 15 minutes.
const healthScript = `#!/bin/sh
# Managed by forge. Host-health checks with per-alert cooldown.
set -u
[ -r /etc/forge/alerts.env ] || exit 0
. /etc/forge/alerts.env
STATE=/var/lib/forge/state
mkdir -p "$STATE"
fresh() { f="$STATE/$1"; [ -f "$f" ] && [ -z "$(find "$f" -mmin +"$2" 2>/dev/null)" ]; }
notify() { /usr/local/lib/forge/notify.sh "$1"; touch "$STATE/$2"; }

CPUS=$(nproc 2>/dev/null || echo 1)
LOAD15=$(awk '{print $3}' /proc/loadavg)
PCT=$(awk -v l="$LOAD15" -v c="$CPUS" 'BEGIN{printf "%d",(l/c)*100}')
if [ "$PCT" -ge "${ALERT_LOAD_PCT:-90}" ] && ! fresh load 360; then
  notify "⚠️ $(hostname): sustained load ${LOAD15} (${PCT}% of ${CPUS} CPUs) — check 'docker stats' / 'top'" load
fi

DISK=$(df -P / | awk 'NR==2{gsub(/%/,"",$5);print $5}')
if [ "$DISK" -ge "${ALERT_DISK_PCT:-85}" ] && ! fresh disk 360; then
  notify "⚠️ $(hostname): root filesystem ${DISK}% full" disk
fi

if [ -f /var/run/reboot-required ] && ! fresh reboot 1440; then
  notify "🔄 $(hostname): reboot required (security updates pending)" reboot
fi
`

// auditNotifyScript runs `forge audit --quiet` and pushes only when it finds
// something. %s is the absolute path of the forge binary.
const auditNotifyScript = `#!/bin/sh
# Managed by forge. Daily compromise/exposure sweep -> Telegram on findings.
set -u
OUT=$(%s audit --quiet 2>/dev/null)
CODE=$?
[ "$CODE" -eq 0 ] && exit 0
/usr/local/lib/forge/notify.sh "🚨 $(hostname): forge audit found issues (severity $CODE):
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

const auditTimer = `[Unit]
Description=Run forge audit once a day

[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
`
