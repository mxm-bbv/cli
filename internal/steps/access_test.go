package steps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAccessUsersList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access", "users")
	if got := readAccessUsers(path); got != nil {
		t.Fatalf("no file: %v", got)
	}
	// A line from forge 0.11: the name alone is a user forge made and allowed.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("s-101\n"), 0o600)
	if got := readAccessUsers(path); len(got) != 1 || got[0] != (AccessUser{Name: "s-101", Allowed: true}) {
		t.Fatalf("0.11 line: %+v", got)
	}

	maks := AccessUser{Name: "maks", Adopted: true}
	if err := setAccessUserIn(path, maks, true); err != nil {
		t.Fatal(err)
	}
	if err := setAccessUserIn(path, AccessUser{Name: "s-101", Allowed: false}, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "maks adopted had\ns-101 made had\n" {
		t.Fatalf("%q", data)
	}
	if got := readAccessUsers(path); len(got) != 2 || got[0] != maks {
		t.Errorf("%+v", got)
	}
	if err := setAccessUserIn(path, maks, false); err != nil {
		t.Fatal(err)
	}
	if got := readAccessUsers(path); len(got) != 1 || got[0].Name != "s-101" {
		t.Errorf("after removing maks: %+v", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
}

func TestWithAccessUser(t *testing.T) {
	dropIn := "# Managed by forge\nPort 22\nAllowUsers deploy root\nPubkeyAuthentication yes\n"
	got, has := withAccessUser(dropIn, "maks", true)
	if !has || got != "# Managed by forge\nPort 22\nAllowUsers deploy root maks\nPubkeyAuthentication yes\n" {
		t.Fatalf("add: %q", got)
	}
	if again, _ := withAccessUser(got, "maks", true); again != got {
		t.Errorf("added twice: %q", again)
	}
	if back, _ := withAccessUser(got, "maks", false); back != dropIn {
		t.Errorf("remove: %q", back)
	}
	if same, has := withAccessUser("Port 22\n", "maks", true); has || same != "Port 22\n" {
		t.Errorf("no AllowUsers: %q %v", same, has)
	}
}
