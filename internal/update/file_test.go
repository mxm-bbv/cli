package update

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// brought is a release a program put on the server, and its SHA256.
func brought(t *testing.T, binary []byte) (path, sum string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "forge-v0.9.0")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, fmt.Sprintf("%x", sha256.Sum256(binary))
}

// autoOff records whether automatic updates were turned off, and how.
func autoOff(t *testing.T, fail error) *[]bool {
	t.Helper()
	var calls []bool
	saved := setAuto
	setAuto = func(on bool) error { calls = append(calls, on); return fail }
	t.Cleanup(func() { setAuto = saved })
	return &calls
}

func TestFromFileInstallsTheReleaseItWasBrought(t *testing.T) {
	self, _ := autoSeams(t, "", nil, nil)
	calls := autoOff(t, nil)
	path, sum := brought(t, fakeForge("v0.9.0", true))

	notes, err := FromFile(path, strings.ToUpper(sum), "v0.9.0", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(version(t, self), "v0.9.0") || !strings.Contains(version(t, self+".prev"), "v0.7.0") {
		t.Errorf("installed %q, kept %q", version(t, self), version(t, self+".prev"))
	}
	if len(*calls) != 0 || len(notes) != 1 {
		t.Errorf("no timer, yet auto %v, notes %q", *calls, notes)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("the program's file is the program's to remove")
	}
}

func TestFromFileTurnsAutomaticUpdatesOff(t *testing.T) {
	autoSeams(t, "", nil, nil)
	if err := os.WriteFile(filepath.Join(UnitDir, "forge-update.timer"), []byte(autoTimer), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := autoOff(t, nil)
	path, sum := brought(t, fakeForge("v0.9.0", true))

	notes, err := FromFile(path, sum, "v0.9.0", os.Getuid())
	if err != nil || len(*calls) != 1 || (*calls)[0] || !strings.Contains(strings.Join(notes, " "), "Automatic updates are off") {
		t.Fatalf("err %v, auto %v, notes %q", err, *calls, notes)
	}

	autoOff(t, errors.New("systemctl failed"))
	path, sum = brought(t, fakeForge("v0.9.0", true))
	if _, err := FromFile(path, sum, "v0.9.0", os.Getuid()); err == nil || !strings.Contains(err.Error(), "still on") {
		t.Errorf("a timer left on went unsaid: %v", err)
	}
}

func TestFromFileRefusesWhatIsntTheRelease(t *testing.T) {
	self, _ := autoSeams(t, "", nil, nil)
	autoOff(t, nil)
	path, sum := brought(t, fakeForge("v0.9.0", true))
	other := strings.Repeat("0", 64)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		path, sum, tag string
		owner          int
		says           string
	}{
		"another sum":   {path, other, "v0.9.0", os.Getuid(), "isn't the release"},
		"not a sum":     {path, "abc", "v0.9.0", os.Getuid(), "64 hex"},
		"not a version": {path, sum, "latest", os.Getuid(), "v1.2.3"},
		"relative":      {"forge-v0.9.0", sum, "v0.9.0", os.Getuid(), "absolute"},
		"a symlink":     {link, sum, "v0.9.0", os.Getuid(), "can't open"},
		"a folder":      {filepath.Dir(path), sum, "v0.9.0", os.Getuid(), "plain file"},
		"someone's":     {path, sum, "v0.9.0", os.Getuid() + 1, "user that asked"},
		"missing":       {path + ".gone", sum, "v0.9.0", os.Getuid(), "can't open"},
	} {
		if os.Getuid() == 0 && name == "someone's" {
			continue // root's own files are always allowed
		}
		if _, err := FromFile(c.path, c.sum, c.tag, c.owner); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !strings.Contains(version(t, self), "v0.7.0") {
		t.Error("forge changed on a refusal")
	}
}

func TestFromFilePutsTheOldOneBackWhenTheNewOneDoesntRun(t *testing.T) {
	self, _ := autoSeams(t, "", nil, nil)
	autoOff(t, nil)

	path, sum := brought(t, fakeForge("v0.9.0", false))
	if _, err := FromFile(path, sum, "v0.9.0", os.Getuid()); err == nil || !strings.Contains(err.Error(), "the one before is back") {
		t.Errorf("a release that doesn't answer: %v", err)
	}
	path, sum = brought(t, fakeForge("v0.8.9", true))
	if _, err := FromFile(path, sum, "v0.9.0", os.Getuid()); err == nil {
		t.Error("a release that says another version was kept")
	}
	if !strings.Contains(version(t, self), "v0.7.0") {
		t.Errorf("now %q", version(t, self))
	}
}
