package update

// Automatic updates: a systemd timer runs `forge update --auto` every 15
// minutes. It asks GitHub which release is the latest (one redirect, no API
// and no rate limit) and installs a newer one the way `forge update` does —
// signature and checksum first, fail closed — keeping the binary it replaces.
// The new binary has to say its version and answer `modules --json`, or the
// old one goes back. Each update, and each one that was undone or refused, is
// a Telegram alert.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/system"
)

const releasesURL = "https://github.com/mxm-bbv/cli/releases"

// Seams for tests.
var (
	StatePath   = "/var/lib/forge/update.json"
	UnitDir     = "/etc/systemd/system"
	latestTag   = LatestTag
	fetchBinary = func(tag, asset string) ([]byte, error) {
		binary, _, err := download(releasesURL+"/download/"+tag, asset, false)
		return binary, err
	}
	notify   = alerts.Send
	selfPath = executable
)

var tagPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// AutoState is what `forge status --json` says about automatic updates.
type AutoState struct {
	On      bool      `json:"on"`
	Checked time.Time `json:"checked,omitzero"`
	Latest  string    `json:"latest,omitempty"`
	Updated time.Time `json:"updated,omitzero"`
	From    string    `json:"from,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// State reads the last check, and whether the timer is set up.
func State() AutoState {
	var st AutoState
	if data, err := os.ReadFile(StatePath); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	st.On = system.FileExists(filepath.Join(UnitDir, "forge-update.timer"))
	return st
}

func saveState(st AutoState) {
	st.On = false // the timer's own file says that
	if data, err := json.Marshal(st); err == nil {
		_ = os.MkdirAll(filepath.Dir(StatePath), 0o700)
		_ = os.WriteFile(StatePath, data, 0o600)
	}
}

// LatestTag asks GitHub where its latest release is: the tag it redirects to.
func LatestTag() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Head(releasesURL + "/latest")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	_, tag, ok := strings.Cut(loc, "/releases/tag/")
	if !ok || !tagPattern.MatchString(tag) {
		return "", fmt.Errorf("GitHub didn't name a release (HTTP %d, %q)", resp.StatusCode, loc)
	}
	return tag, nil
}

// Newer: latest is a later release than current. A build that isn't a
// release ("dev") is never replaced on its own.
func Newer(current, latest string) bool {
	a, b := tagPattern.FindStringSubmatch(current), tagPattern.FindStringSubmatch(latest)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return y > x
		}
	}
	return false
}

// Auto is `forge update --auto`, what the timer runs.
func Auto(current string) int {
	st := State()
	st.Checked = time.Now().UTC()
	defer func() { saveState(st) }()

	latest, err := latestTag()
	if err != nil {
		st.Error = "couldn't ask GitHub: " + err.Error()
		return 1
	}
	st.Latest = latest
	if !Newer(current, latest) {
		st.Error = ""
		return 0
	}

	self, err := selfPath()
	if err != nil {
		st.Error = err.Error()
		return 1
	}
	binary, err := fetchBinary(latest, "forge-linux-"+runtime.GOARCH)
	if err != nil {
		st.Error = latest + ": " + err.Error()
		// A release that doesn't verify is either broken or not ours: say so once a day.
		_ = notify(alerts.Alert{Text: "🚨 forge " + latest + " wasn't installed: " + err.Error() + ". " + current + " stays.", Key: "forge-update-refused:" + latest, Every: 24 * time.Hour, Urgent: true})
		return 1
	}
	if err := replace(self, binary, true); err != nil {
		st.Error = latest + ": " + err.Error()
		return 1
	}
	if err := runs(self, latest); err != nil {
		if rerr := os.Rename(self+".prev", self); rerr != nil {
			err = fmt.Errorf("%v, and putting %s back failed too: %v", err, current, rerr)
		}
		st.Error = latest + " didn't run here: " + err.Error()
		_ = notify(alerts.Alert{Text: "⚠️ forge " + latest + " didn't run here (" + err.Error() + "), so " + current + " is back.", Key: "forge-update-undone:" + latest, Every: 24 * time.Hour, Urgent: true})
		return 1
	}

	st.Updated, st.From, st.Error = time.Now().UTC(), current, ""
	_ = notify(alerts.Alert{Text: "⬆️ forge updated itself: " + current + " → " + latest, Key: "forge-updated:" + latest, Every: 24 * time.Hour})
	// The new release writes its own timer: it may run it differently.
	_ = osexec.Command(self, "update", "auto", "refresh").Run()
	return 0
}

// runs checks a freshly installed forge: it says the version it was released
// as and answers a program, as deploy.me will ask it.
func runs(self, tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := osexec.CommandContext(ctx, self, "--version").Output()
	if err != nil {
		return fmt.Errorf("--version: %w", err)
	}
	if !strings.Contains(string(out), tag) {
		return fmt.Errorf("it says %q", strings.TrimSpace(string(out)))
	}
	out, err = osexec.CommandContext(ctx, self, "modules", "--json").Output()
	if err != nil || !json.Valid(out) {
		return errors.New("modules --json didn't answer")
	}
	return nil
}

func executable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return self, nil
}

// SetAuto turns automatic updates on (the timer, enabled now) or off.
func SetAuto(on bool) error {
	service, timer := filepath.Join(UnitDir, "forge-update.service"), filepath.Join(UnitDir, "forge-update.timer")
	if !on {
		_, _ = system.Run("systemctl", "disable", "--now", "forge-update.timer")
		for _, p := range []string{timer, service} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		_, err := system.Run("systemctl", "daemon-reload")
		return err
	}
	self, err := executable()
	if err != nil {
		return err
	}
	if err := system.WriteFile(service, fmt.Sprintf(autoService, self), 0o644); err != nil {
		return err
	}
	if err := system.WriteFile(timer, autoTimer, 0o644); err != nil {
		return err
	}
	if _, err := system.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err = system.Run("systemctl", "enable", "--now", "forge-update.timer")
	return err
}

// Refresh rewrites the timer's units for this binary, where they're set up.
func Refresh() error {
	if !State().On {
		return nil
	}
	return SetAuto(true)
}

// autoService: %s is the forge binary.
const autoService = `[Unit]
Description=forge: install a newer signed release of itself
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s update --auto
Nice=10
`

const autoTimer = `[Unit]
Description=Look for a newer forge every 15 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=15min
RandomizedDelaySec=3min
Persistent=true

[Install]
WantedBy=timers.target
`
