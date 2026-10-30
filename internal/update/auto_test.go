package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/alerts"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		current, latest string
		want            bool
	}{
		{"v0.7.0", "v0.7.1", true},
		{"v0.7.9", "v0.8.0", true},
		{"v0.9.0", "v1.0.0", true},
		{"v0.7.1", "v0.7.1", false},
		{"v0.8.0", "v0.7.9", false},
		{"v0.10.0", "v0.9.0", false},
		{"dev", "v0.7.1", false},
		{"v0.7.0", "latest", false},
	} {
		if got := Newer(c.current, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.current, c.latest, got)
		}
	}
}

// fakeForge is a release binary as a shell script: it says its version and
// answers modules --json, or doesn't.
func fakeForge(version string, answers bool) []byte {
	modules := `echo '{"modules":[]}'`
	if !answers {
		modules = "exit 3"
	}
	return []byte("#!/bin/sh\ncase \"$1\" in\n--version) echo \"forge " + version + "\" ;;\nmodules) " + modules + " ;;\nesac\n")
}

func autoSeams(t *testing.T, latest string, binary []byte, fetchErr error) (self string, sent *[]alerts.Alert) {
	t.Helper()
	dir := t.TempDir()
	self = filepath.Join(dir, "forge")
	if err := os.WriteFile(self, fakeForge("v0.7.0", true), 0o755); err != nil {
		t.Fatal(err)
	}
	var got []alerts.Alert
	saved := []any{StatePath, UnitDir, latestTag, fetchBinary, notify, selfPath}
	StatePath, UnitDir = filepath.Join(dir, "update.json"), dir
	latestTag = func() (string, error) { return latest, nil }
	fetchBinary = func(tag, asset string) ([]byte, error) { return binary, fetchErr }
	notify = func(a alerts.Alert) error { got = append(got, a); return nil }
	selfPath = func() (string, error) { return self, nil }
	t.Cleanup(func() {
		StatePath, UnitDir = saved[0].(string), saved[1].(string)
		latestTag = saved[2].(func() (string, error))
		fetchBinary = saved[3].(func(string, string) ([]byte, error))
		notify = saved[4].(func(alerts.Alert) error)
		selfPath = saved[5].(func() (string, error))
	})
	return self, &got
}

func version(t *testing.T, self string) string {
	t.Helper()
	data, _ := os.ReadFile(self)
	return string(data)
}

func TestAutoInstallsANewerRelease(t *testing.T) {
	self, sent := autoSeams(t, "v0.7.1", fakeForge("v0.7.1", true), nil)

	if code := Auto("v0.7.0"); code != 0 {
		t.Fatalf("exit %d: %+v", code, State())
	}
	if !strings.Contains(version(t, self), "v0.7.1") || !strings.Contains(version(t, self+".prev"), "v0.7.0") {
		t.Error("the new release isn't in place, or the old one wasn't kept")
	}
	st := State()
	if st.From != "v0.7.0" || st.Latest != "v0.7.1" || st.Updated.IsZero() || st.Error != "" {
		t.Errorf("state %+v", st)
	}
	if len(*sent) != 1 || !strings.Contains((*sent)[0].Text, "v0.7.0 → v0.7.1") || (*sent)[0].Urgent {
		t.Errorf("alerts %+v", *sent)
	}
}

func TestAutoLeavesTheSameRelease(t *testing.T) {
	self, sent := autoSeams(t, "v0.7.0", nil, errors.New("not asked"))
	if code := Auto("v0.7.0"); code != 0 || len(*sent) != 0 || !strings.Contains(version(t, self), "v0.7.0") {
		t.Errorf("exit %d, alerts %+v", code, *sent)
	}
	if st := State(); st.Checked.IsZero() || st.Latest != "v0.7.0" {
		t.Errorf("state %+v", st)
	}
}

func TestAutoPutsTheOldOneBackWhenTheNewOneDoesntRun(t *testing.T) {
	self, sent := autoSeams(t, "v0.7.1", fakeForge("v0.7.1", false), nil)

	if code := Auto("v0.7.0"); code == 0 {
		t.Fatal("a release that doesn't answer was kept")
	}
	if !strings.Contains(version(t, self), "v0.7.0") {
		t.Error("v0.7.0 isn't back")
	}
	if len(*sent) != 1 || !(*sent)[0].Urgent || !strings.Contains((*sent)[0].Text, "v0.7.0 is back") {
		t.Errorf("alerts %+v", *sent)
	}
	if st := State(); !strings.Contains(st.Error, "didn't run") {
		t.Errorf("state %+v", st)
	}
}

func TestAutoRefusesAReleaseThatDoesntVerify(t *testing.T) {
	self, sent := autoSeams(t, "v0.7.1", nil, errors.New("checksum mismatch"))

	if code := Auto("v0.7.0"); code == 0 || !strings.Contains(version(t, self), "v0.7.0") {
		t.Fatalf("exit %d", code)
	}
	if len(*sent) != 1 || !(*sent)[0].Urgent || !strings.Contains((*sent)[0].Text, "wasn't installed") {
		t.Errorf("alerts %+v", *sent)
	}
}

func TestStateSaysWhetherTheTimerIsThere(t *testing.T) {
	autoSeams(t, "v0.7.0", nil, nil)
	if State().On {
		t.Error("on without a timer")
	}
	if err := os.WriteFile(filepath.Join(UnitDir, "forge-update.timer"), []byte(autoTimer), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(State())
	if !State().On || !strings.Contains(string(data), `"on":true`) {
		t.Errorf("got %s", data)
	}
}
