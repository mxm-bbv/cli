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
	for _, step := range []struct {
		name string
		on   bool
		want []string
	}{
		{"s-101", true, []string{"s-101"}},
		{"s-102", true, []string{"s-101", "s-102"}},
		{"s-101", true, []string{"s-102", "s-101"}},
		{"s-102", false, []string{"s-101"}},
		{"s-404", false, []string{"s-101"}},
	} {
		if err := setAccessUserIn(path, step.name, step.on); err != nil {
			t.Fatal(err)
		}
		if got := readAccessUsers(path); len(got) != len(step.want) || (len(got) > 0 && got[len(got)-1] != step.want[len(step.want)-1]) {
			t.Errorf("%s %v: %v, want %v", step.name, step.on, got, step.want)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
}

func TestWithAccessUser(t *testing.T) {
	dropIn := "# Managed by forge\nPort 22\nAllowUsers deploy root\nPubkeyAuthentication yes\n"
	got, has := withAccessUser(dropIn, "s-101", true)
	if !has || got != "# Managed by forge\nPort 22\nAllowUsers deploy root s-101\nPubkeyAuthentication yes\n" {
		t.Fatalf("add: %q", got)
	}
	if again, _ := withAccessUser(got, "s-101", true); again != got {
		t.Errorf("added twice: %q", again)
	}
	if back, _ := withAccessUser(got, "s-101", false); back != dropIn {
		t.Errorf("remove: %q", back)
	}
	if same, has := withAccessUser("Port 22\n", "s-101", true); has || same != "Port 22\n" {
		t.Errorf("no AllowUsers: %q %v", same, has)
	}
}
