package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// newKey makes a key with ssh-keygen and returns its public line and the
// fingerprint ssh-keygen gives it.
func newKey(t *testing.T, comment string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	pub, _ := os.ReadFile(path + ".pub")
	out, err := exec.Command("ssh-keygen", "-lf", path+".pub").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pub)), strings.Fields(string(out))[1]
}

func TestParseAuthorizedKey(t *testing.T) {
	line, fp := newKey(t, "farset@DESKTOP-7OK13B3")
	for _, l := range []string{line, `restrict,command="echo ssh-ed25519 x" ` + line, "expiry-time=\"20261231\" " + line} {
		k, ok := parseAuthorizedKey(l)
		if !ok || k.Fingerprint != fp || k.Type != "ssh-ed25519" || k.Comment != "farset@DESKTOP-7OK13B3" {
			t.Errorf("%q: %+v %v, want %s", l, k, ok, fp)
		}
	}
	if k, _ := parseAuthorizedKey(`command="x" ` + line); k.Options != `command="x"` {
		t.Errorf("options: %q", k.Options)
	}
	for _, l := range []string{"", "# " + line, "ssh-ed25519 notbase64", "ssh-rsa " + strings.Fields(line)[1]} {
		if k, ok := parseAuthorizedKey(l); ok {
			t.Errorf("%q read as %+v", l, k)
		}
	}
}

func TestDropKeys(t *testing.T) {
	mod, modFP := newKey(t, "studio-os")
	other, otherFP := newKey(t, "farset@DESKTOP-7OK13B3")
	content := "# keys\n" + mod + "\n" + other + "\n"

	body, removed, err := dropKeys(content, []string{otherFP}, modFP, true)
	if err != nil || body != "# keys\n"+mod+"\n" || len(removed) != 1 || removed[0] != otherFP {
		t.Fatalf("drop: %q %v %v", body, removed, err)
	}
	if _, _, err := dropKeys(content, []string{modFP}, modFP, true); err == nil {
		t.Error("dropped the module's key")
	}
	if _, _, err := dropKeys(other+"\n", []string{otherFP}, modFP, false); err == nil {
		t.Error("went on without the module's key in the file")
	}
	if _, _, err := dropKeys(other+"\n", []string{otherFP}, "", true); err == nil {
		t.Error("left forge's user with no key")
	}
	if body, _, err := dropKeys(other+"\n", []string{otherFP}, "", false); err != nil || body != "" {
		t.Errorf("another user's last key: %q %v", body, err)
	}
	if _, _, err := dropKeys(content, nil, modFP, true); err != nil {
		t.Errorf("nothing to drop: %v", err)
	}
}

func TestAccessDropKeepsTheOldFile(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	mod, modFP := newKey(t, "studio-os")
	other, otherFP := newKey(t, "maks")
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	os.WriteFile(ak, []byte(mod+"\n"+other+"\n"), 0o644)
	u := *me
	u.HomeDir = home
	backups := filepath.Join(t.TempDir(), "access")

	gone := "SHA256:" + strings.Repeat("A", 43)
	removed, missing, err := accessDrop(&u, []string{otherFP, gone}, modFP, true, backups)
	if err != nil || len(removed) != 1 || len(missing) != 1 || missing[0] != gone {
		t.Fatalf("%v %v %v", removed, missing, err)
	}
	data, _ := os.ReadFile(ak)
	info, _ := os.Stat(ak)
	if string(data) != mod+"\n" || info.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys %o: %q", info.Mode().Perm(), data)
	}
	old, _ := filepath.Glob(filepath.Join(backups, u.Username+"-*.authorized_keys"))
	if len(old) != 1 {
		t.Fatalf("backups: %v", old)
	}
	if was, _ := os.ReadFile(old[0]); string(was) != mod+"\n"+other+"\n" {
		t.Errorf("backup: %q", was)
	}
}

func TestAccessList(t *testing.T) {
	line, fp := newKey(t, "maks")
	root, maks, svc := t.TempDir(), t.TempDir(), t.TempDir()
	for _, h := range []string{root, maks} {
		os.MkdirAll(filepath.Join(h, ".ssh"), 0o700)
	}
	os.WriteFile(filepath.Join(root, ".ssh", "authorized_keys"), []byte(""), 0o600)
	os.WriteFile(filepath.Join(maks, ".ssh", "authorized_keys"), []byte("# hi\n"+line+"\n"), 0o600)
	passwd := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(passwd, []byte(strings.Join([]string{
		"maks:x:1001:1001::" + maks + ":/bin/bash",
		"www-data:x:33:33::" + svc + ":/usr/sbin/nologin",
		"root:x:0:0:root:" + root + ":/bin/bash",
	}, "\n")), 0o644)

	users, err := accessList(passwd, func(name string) []string { return []string{name, "sudo"} })
	if err != nil || len(users) != 2 {
		t.Fatalf("%+v %v", users, err)
	}
	if users[0].User != "root" || len(users[0].Keys) != 0 {
		t.Errorf("root first, no keys: %+v", users[0])
	}
	if u := users[1]; u.User != "maks" || u.UID != 1001 || len(u.Keys) != 1 || u.Keys[0].Fingerprint != fp || u.Groups[1] != "sudo" {
		t.Errorf("maks: %+v", u)
	}
}

func TestFingerprints(t *testing.T) {
	a := "SHA256:" + strings.Repeat("a", 43)
	got, err := fingerprints(a + "\n " + a + "\nSHA256:" + strings.Repeat("b", 43))
	if err != nil || len(got) != 2 {
		t.Errorf("%v %v", got, err)
	}
	for _, s := range []string{"MD5:aa", "SHA256:short", a + ";rm"} {
		if _, err := fingerprints(s); err == nil {
			t.Errorf("%q passed", s)
		}
	}
}
