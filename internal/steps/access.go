package steps

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// AccessUsersFile lists the users forge lets in for access grants
// (access-grant), one a line: `<name> made|adopted added|had`. Only those are
// ever granted to or taken back. A user forge made is removed with its last
// grant; one it adopted (on the server before) stays, and leaves AllowUsers
// only if forge put it there.
const AccessUsersFile = "/var/lib/forge/access/users"

// AccessUser is one user of an access grant.
type AccessUser struct {
	Name    string
	Adopted bool // on the server before the first grant: never removed
	Allowed bool // forge put it in AllowUsers (rather than it being there already)
}

// AccessUsers are the users of access grants.
func AccessUsers() []AccessUser {
	return readAccessUsers(AccessUsersFile)
}

// FindAccessUser is the user of access grants by that name.
func FindAccessUser(name string) (AccessUser, bool) {
	for _, u := range AccessUsers() {
		if u.Name == name {
			return u, true
		}
	}
	return AccessUser{}, false
}

func readAccessUsers(path string) []AccessUser {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []AccessUser
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || slices.ContainsFunc(out, func(u AccessUser) bool { return u.Name == f[0] }) {
			continue
		}
		// A line with the name alone is from forge 0.11: a user it made and allowed.
		u := AccessUser{Name: f[0], Allowed: true}
		if len(f) > 1 {
			u.Adopted = f[1] == "adopted"
		}
		if len(f) > 2 {
			u.Allowed = f[2] == "added"
		}
		out = append(out, u)
	}
	return out
}

// SetAccessUser puts a user on the list (replacing its line) or takes it off.
func SetAccessUser(u AccessUser, on bool) error {
	return setAccessUserIn(AccessUsersFile, u, on)
}

func setAccessUserIn(path string, u AccessUser, on bool) error {
	users := slices.DeleteFunc(readAccessUsers(path), func(x AccessUser) bool { return x.Name == u.Name })
	if on {
		users = append(users, u)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	for _, x := range users {
		mode, allow := "made", "had"
		if x.Adopted {
			mode = "adopted"
		}
		if x.Allowed {
			allow = "added"
		}
		fmt.Fprintf(&b, "%s %s %s\n", x.Name, mode, allow)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// allowedAccessUsers are the users forge itself put in AllowUsers: setup run
// again keeps them in.
func allowedAccessUsers() []string {
	var out []string
	for _, u := range AccessUsers() {
		if u.Allowed {
			out = append(out, u.Name)
		}
	}
	return out
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

// SSHAllows says whether forge's AllowUsers lets this user in already (true
// also when there's no AllowUsers, so sshd lets everyone in).
func SSHAllows(name string) bool {
	dropIn, _ := readFileOrEmpty(sshdDropInPath)
	for _, l := range strings.Split(dropIn, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && strings.EqualFold(f[0], "AllowUsers") {
			return slices.Contains(f[1:], name)
		}
	}
	return true
}

// AllowAccessUser lets a user through forge's AllowUsers, or no longer: sshd -t
// first, the old file back if it refuses, then a reload so open sessions stay.
// Without forge's AllowUsers sshd lets everyone in already.
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
