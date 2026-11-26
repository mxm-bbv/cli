package steps

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// AccessUsersFile lists the personal users forge made for access grants
// (access-grant), one a line: only those may be granted to or removed.
const AccessUsersFile = "/var/lib/forge/access/users"

// AccessUsers are the personal users forge made for access grants.
func AccessUsers() []string {
	return readAccessUsers(AccessUsersFile)
}

func readAccessUsers(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

// SetAccessUser adds a user to the list or takes it off.
func SetAccessUser(name string, on bool) error {
	return setAccessUserIn(AccessUsersFile, name, on)
}

func setAccessUserIn(path, name string, on bool) error {
	users := slices.DeleteFunc(readAccessUsers(path), func(u string) bool { return u == name })
	if on {
		users = append(users, name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body := strings.Join(users, "\n")
	if body != "" {
		body += "\n"
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

// withAccessUser is forge's AllowUsers line with a user added or taken off;
// the content as it was when there's no AllowUsers line (sshd lets everyone in).
func withAccessUser(dropIn, name string, on bool) (string, bool) {
	lines := strings.Split(dropIn, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 || !strings.EqualFold(f[0], "AllowUsers") {
			continue
		}
		users := slices.DeleteFunc(slices.Clone(f[1:]), func(u string) bool { return u == name })
		if on {
			users = append(users, name)
		}
		lines[i] = "AllowUsers " + strings.Join(users, " ")
		return strings.Join(lines, "\n"), true
	}
	return dropIn, false
}

// AllowAccessUser lets a personal user through forge's AllowUsers, or no
// longer: sshd -t first, the old file back if it refuses, then a reload so
// open sessions stay. Without forge's AllowUsers sshd lets everyone in already.
func AllowAccessUser(name string, on bool) error {
	prev, err := readFileOrEmpty(sshdDropInPath)
	if err != nil || prev == "" {
		return err
	}
	next, has := withAccessUser(prev, name, on)
	if !has || next == prev {
		return nil
	}
	if err := system.WriteFile(sshdDropInPath, next, 0o644); err != nil {
		return err
	}
	ensureSSHDRuntimeDir()
	if _, err := system.Run("sshd", "-t"); err != nil {
		_ = restoreFile(sshdDropInPath, prev)
		return fmt.Errorf("sshd refuses AllowUsers with %s, nothing changed: %w", name, err)
	}
	if err := reloadSSHD(); err != nil {
		_ = restoreFile(sshdDropInPath, prev)
		_ = reloadSSHD()
		return fmt.Errorf("sshd didn't reload, nothing changed: %w", err)
	}
	return nil
}
