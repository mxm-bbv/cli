package steps

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func keygen(t, path string) error {
	return exec.Command("ssh-keygen", "-q", "-t", t, "-N", "", "-f", path).Run()
}

// hostKeysDir is an /etc/ssh with an ed25519 and an rsa host key.
func hostKeysDir(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	dir := t.TempDir()
	for _, k := range []string{"ed25519", "rsa"} {
		if err := keygen(k, filepath.Join(dir, "ssh_host_"+k+"_key")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRenewHostKeys(t *testing.T) {
	dir := hostKeysDir(t)
	oldPub := read(t, filepath.Join(dir, "ssh_host_ed25519_key.pub"))
	backup := filepath.Join(t.TempDir(), "old")
	reloaded := false

	keys, err := renewHostKeysIn(dir, backup, keygen, func() error { return nil }, func() error { reloaded = true; return nil })
	if err != nil || len(keys) != 2 || !reloaded {
		t.Fatalf("%+v %v reloaded=%v", keys, err, reloaded)
	}
	newPub := read(t, filepath.Join(dir, "ssh_host_ed25519_key.pub"))
	if newPub == oldPub || keys[0].Type != "ssh-ed25519" || !strings.HasPrefix(newPub, keys[0].Public) || keys[1].Type != "ssh-rsa" {
		t.Errorf("keys %+v, file %q", keys, newPub)
	}
	if read(t, filepath.Join(backup, "ssh_host_ed25519_key.pub")) != oldPub {
		t.Error("the old key isn't kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "ssh_host_ecdsa_key")); err == nil {
		t.Error("made a type the server didn't have")
	}
	if info, _ := os.Stat(filepath.Join(dir, "ssh_host_ed25519_key")); info.Mode().Perm() != 0o600 {
		t.Errorf("private key %o", info.Mode().Perm())
	}
}

func TestRenewHostKeysPutsTheOldOnesBack(t *testing.T) {
	for name, fail := range map[string]struct{ check, reload error }{
		"sshd -t":   {check: errors.New("bad")},
		"reloading": {reload: errors.New("failed")},
	} {
		dir := hostKeysDir(t)
		oldKey := read(t, filepath.Join(dir, "ssh_host_ed25519_key"))
		oldPub := read(t, filepath.Join(dir, "ssh_host_rsa_key.pub"))
		_, err := renewHostKeysIn(dir, filepath.Join(t.TempDir(), "old"), keygen, func() error { return fail.check }, func() error { return fail.reload })
		if err == nil || !strings.Contains(err.Error(), "old ones are back") {
			t.Errorf("%s: %v", name, err)
		}
		if read(t, filepath.Join(dir, "ssh_host_ed25519_key")) != oldKey || read(t, filepath.Join(dir, "ssh_host_rsa_key.pub")) != oldPub {
			t.Errorf("%s: the old keys aren't back", name)
		}
	}
	if _, err := renewHostKeysIn(t.TempDir(), filepath.Join(t.TempDir(), "old"), keygen, nil, nil); err == nil {
		t.Error("renewed keys a server doesn't have")
	}
}
