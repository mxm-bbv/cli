package steps

import (
	"fmt"
	"os"
	"strings"

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
	sshrcPath       = "/etc/ssh/sshrc"
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

			// SSH-login alert via /etc/ssh/sshrc — safer than editing PAM: a
			// failure here can never lock anyone out, and it is backgrounded.
			if cfg.AlertOnSSHLogin {
				if err := installSSHRC(); err != nil {
					return err
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

// installSSHRC appends the forge login-alert block to /etc/ssh/sshrc exactly
// once, preserving any existing content.
func installSSHRC() error {
	const marker = "# forge-ssh-login-alert"
	if system.FileContains(sshrcPath, marker) {
		return nil
	}
	existing, err := readFileOrEmpty(sshrcPath)
	if err != nil {
		return err
	}
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return system.WriteFile(sshrcPath, existing+sshrcBlock, 0o644)
}

// notifyScript reads a message from $1 (or stdin) and pushes it to Telegram.
// --data-urlencode keeps arbitrary text safe — no JSON escaping, no injection.
const notifyScript = `#!/bin/sh
# Managed by forge. Sends its argument (or stdin) to Telegram.
set -u
. /etc/forge/alerts.env 2>/dev/null || exit 0
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] || exit 0
[ -n "${TELEGRAM_CHAT_ID:-}" ] || exit 0
if [ $# -gt 0 ]; then MSG="$1"; else MSG="$(cat)"; fi
curl -fsS --max-time 15 -X POST \
  "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
  --data-urlencode "text=${MSG}" \
  -d disable_web_page_preview=true >/dev/null
`

// healthScript warns on sustained load, disk pressure and pending reboots,
// each rate-limited by a state file so a standing condition alerts once, not
// every 15 minutes.
const healthScript = `#!/bin/sh
# Managed by forge. Host-health checks with per-alert cooldown.
set -u
. /etc/forge/alerts.env 2>/dev/null || exit 0
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

const sshrcBlock = `# forge-ssh-login-alert
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
