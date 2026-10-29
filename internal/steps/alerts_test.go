package steps

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/config"
)

// alerts.env is sourced by root's shell scripts: a name with spaces and a
// list of networks must arrive as one word each, and run nothing.
func TestAlertsEnvIsSafeToSource(t *testing.T) {
	cfg := config.Default()
	cfg.TelegramBotToken, cfg.AlertsChatID = "123456789:AAexampleexampleexampleexampleexample", "-1001234567890"
	cfg.AlertName, cfg.AlertLogins = "Votonia VPS (prod) #1", alerts.LoginsNew
	quiet, err := alerts.ParseQuiet("2.135.53.39 100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(t.TempDir(), "alerts.env")
	if err := os.WriteFile(env, []byte(alertsEnv(cfg, quiet)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", `. "$1" && printf '%s|%s|%s|%s' "$ALERT_NAME" "$ALERT_QUIET_FROM" "$ALERT_SSH_LOGIN" "$TELEGRAM_CHAT_ID"`, "sh", env).CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing failed: %v\n%s", err, out)
	}
	if got := string(out); got != "Votonia VPS (prod) #1|2.135.53.39/32 100.64.0.0/10|new|-1001234567890" {
		t.Fatalf("the shell read %q", got)
	}

	// And Go reads the same file back.
	set := alerts.SettingsFrom(alerts.ParseEnv(alertsEnv(cfg, quiet)))
	if !set.Configured || set.Name != cfg.AlertName || set.Logins != alerts.LoginsNew || len(set.Quiet) != 2 || set.MaxPerHour != alerts.DefaultMaxPerHour {
		t.Fatalf("Go read %+v", set)
	}
}

// The scripts name this forge binary, not whatever "forge" PATH finds.
func TestAlertScriptsCallThisForge(t *testing.T) {
	for name, script := range map[string]string{"login": loginNotifyScript, "health": healthScript, "audit": auditNotifyScript} {
		got := withForge(script, "/usr/local/bin/forge")
		if strings.Contains(got, "@FORGE@") || !strings.Contains(got, "/usr/local/bin/forge alert ") {
			t.Errorf("%s script:\n%s", name, got)
		}
	}
	if !strings.Contains(auditNotifyScript, "alert send --urgent") {
		t.Error("audit findings must not wait behind the hourly limit")
	}
	if strings.Contains(loginNotifyScript, "notify.sh") || strings.Contains(healthScript, "notify.sh") {
		t.Error("a script still talks to Telegram past forge alert")
	}
}
