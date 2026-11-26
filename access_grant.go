package main

// A person's own way in, with a term (Studio OS access grants):
//
//	access-grant   the person's user (made if missing: no password; a user
//	               already on the server is adopted, never root or the
//	               deploy user) and one line in its authorized_keys — the key
//	               and until when sshd lets it in (expiry-time), signed
//	               studio-os:<grant>. Kind admin: a shell and sudo (its own
//	               sudoers.d file); kind tunnel: no shell, one port forward.
//	access-revoke  takes that line away; with no admin grant left the sudoers
//	               file goes; with no grant left the user is logged out, leaves
//	               AllowUsers if forge put it there, and is removed if forge
//	               made it
//
// Only users of grants (steps.AccessUsersFile) are ever touched.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

var (
	grantIDRe = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	expiresRe = regexp.MustCompile(`^[0-9]{12}$`)
)

const (
	kindTunnel = "tunnel"
	kindAdmin  = "admin"
	// sudoersDir holds one file per admin user: forge-access-<name>.
	sudoersDir = "/etc/sudoers.d"
)

// grantMarker ends each authorized_keys line a grant adds.
func grantMarker(grant string) string { return "studio-os:" + grant }

// grantLine is the authorized_keys line of a grant, until the moment given.
// tunnel: no shell, no pty, only a forward to one port on the server's
// loopback. admin: a shell like any key, with the term. sshd reads
// expiry-time in the server's own time zone (a trailing Z isn't known to
// every OpenSSH a server may have).
func grantLine(kind string, key accessKey, blob, grant string, until time.Time, port int) string {
	expiry := until.In(time.Local).Format("200601021504")
	if kind == kindAdmin {
		return fmt.Sprintf(`expiry-time="%s" %s %s %s`, expiry, key.Type, blob, grantMarker(grant))
	}
	return fmt.Sprintf(`restrict,port-forwarding,permitopen="127.0.0.1:%d",expiry-time="%s" %s %s %s`,
		port, expiry, key.Type, blob, grantMarker(grant))
}

// withGrant is authorized_keys with the grant's line put in (in place of an
// earlier one of the same grant) or, with line "", taken out; and how many
// grant lines are left, and how many of them are admin's (no `restrict`).
func withGrant(content, grant, line string) (string, int, int) {
	var kept []string
	left, admins := 0, 0
	count := func(l string) {
		if strings.Contains(l, " studio-os:") {
			left++
			if !strings.HasPrefix(l, "restrict") {
				admins++
			}
		}
	}
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if l == "" || strings.HasSuffix(l, " "+grantMarker(grant)) {
			continue
		}
		count(l)
		kept = append(kept, l)
	}
	if line != "" {
		kept = append(kept, line)
		count(line)
	}
	body := strings.Join(kept, "\n")
	if body != "" {
		body += "\n"
	}
	return body, left, admins
}

// grantUser checks a grant's user name: a valid one, never root or the user
// forge works for (the deploy user a program signs in as).
func grantUser(name string) error {
	if err := config.ValidUsername(name); err != nil {
		return fmt.Errorf("user: %w", err)
	}
	if name == "root" || name == os.Getenv("SUDO_USER") {
		return fmt.Errorf("user: %s is not given to a person", name)
	}
	if u, err := user.Lookup(name); err == nil && u.Uid == strconv.Itoa(sudoUID()) {
		return fmt.Errorf("user: %s is not given to a person", name)
	}
	return nil
}

// grantInputs checks access-grant's inputs: the key, its base64, the port
// (tunnel) and the moment the grant ends.
func grantInputs(in map[string]string, now time.Time) (accessKey, string, int, time.Time, error) {
	var zero time.Time
	if !grantIDRe.MatchString(in["grant"]) {
		return accessKey{}, "", 0, zero, errors.New("grant: a-z, 0-9 and -, up to 40")
	}
	if err := grantUser(in["user"]); err != nil {
		return accessKey{}, "", 0, zero, err
	}
	if in["kind"] != kindTunnel && in["kind"] != kindAdmin {
		return accessKey{}, "", 0, zero, errors.New("kind: tunnel or admin")
	}
	key, ok := parseAuthorizedKey(in["key"])
	if !ok || key.Options != "" {
		return accessKey{}, "", 0, zero, errors.New("key: one public key, type and base64, no options")
	}
	blob := strings.Fields(in["key"])[1]
	if !expiresRe.MatchString(in["expires"]) {
		return accessKey{}, "", 0, zero, errors.New("expires: YYYYMMDDHHMM in UTC")
	}
	until, err := time.Parse("200601021504", in["expires"])
	if err != nil || !until.After(now) {
		return accessKey{}, "", 0, zero, errors.New("expires: a moment still to come")
	}
	port := 0
	if in["kind"] == kindTunnel {
		if port, err = strconv.Atoi(in["port"]); err != nil || port < 1 || port > 65535 {
			return accessKey{}, "", 0, zero, errors.New("port: 1-65535")
		}
	}
	return key, blob, port, until, nil
}

// ensureAccessUser makes the user, or adopts one already on the server (a
// person's own, uid 1000 and up). An admin grant needs a login shell: a user
// forge made gets bash, an adopted one must have its own.
func ensureAccessUser(name, kind string) (*user.User, error) {
	known, listed := steps.FindAccessUser(name)
	u, err := user.Lookup(name)
	if err != nil {
		shell := "/usr/sbin/nologin"
		if kind == kindAdmin {
			shell = "/bin/bash"
		}
		if _, err := system.Run("groupadd", "-f", "forge-access"); err != nil {
			return nil, err
		}
		if _, err := system.Run("useradd", "-m", "-s", shell, "-G", "forge-access", "-c", "Studio OS access", name); err != nil {
			return nil, err
		}
		// "*": no password to sign in with, and not "locked" (a "!" would keep sshd from letting the key in).
		if _, err := system.Run("usermod", "-p", "*", name); err != nil {
			return nil, err
		}
		if err := steps.SetAccessUser(steps.AccessUser{Name: name, Allowed: !steps.SSHAllows(name)}, true); err != nil {
			return nil, err
		}
		return user.Lookup(name)
	}
	if !listed {
		if uid, _ := strconv.Atoi(u.Uid); uid < 1000 {
			return nil, fmt.Errorf("%s is a system user: refused", name)
		}
		known = steps.AccessUser{Name: name, Adopted: true, Allowed: !steps.SSHAllows(name)}
		if err := steps.SetAccessUser(known, true); err != nil {
			return nil, err
		}
	}
	if kind == kindAdmin {
		shell := loginShell(name)
		switch {
		case !known.Adopted && !strings.HasSuffix(shell, "sh"):
			if _, err := system.Run("usermod", "-s", "/bin/bash", name); err != nil {
				return nil, err
			}
		case known.Adopted && !strings.HasSuffix(shell, "sh"):
			return nil, fmt.Errorf("%s has no login shell (%s): refused", name, shell)
		}
	}
	return u, nil
}

// loginShell is a user's shell from /etc/passwd.
func loginShell(name string) string {
	data, _ := os.ReadFile("/etc/passwd")
	for _, l := range strings.Split(string(data), "\n") {
		if p := strings.Split(l, ":"); len(p) >= 7 && p[0] == name {
			return p[6]
		}
	}
	return ""
}

func sudoersPath(name string) string { return filepath.Join(sudoersDir, "forge-access-"+name) }

// allowSudo gives an admin user sudo with its own sudoers.d file, checked by
// visudo before it's put in place; or takes the file away.
func allowSudo(name string, on bool) error {
	path := sudoersPath(name)
	if !on {
		return system.RemoveFile(path)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(name+" ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
		return err
	}
	if _, err := system.Run("visudo", "-cf", tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("visudo refuses sudo for %s: %w", name, err)
	}
	return os.Rename(tmp, path)
}

// writeAuthorizedKeys writes a user's authorized_keys: 0600, theirs, in one move.
func writeAuthorizedKeys(u *user.User, body string) error {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	dir := filepath.Join(u.HomeDir, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	path := filepath.Join(dir, "authorized_keys")
	tmp := path + ".forge-access"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func readAuthorizedKeys(u *user.User) string {
	data, _ := os.ReadFile(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"))
	return string(data)
}

var grantModules = []module{
	{
		Name:        "access-grant",
		Title:       "Let a person in",
		Description: "The person's user (made if missing; one already on the server is adopted, never root or the deploy user) gets one key line with a term (expiry-time), signed studio-os:<grant>, and gets through forge's AllowUsers. admin: a shell and sudo; tunnel: one port forward, no shell. The same grant again replaces its line.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "grant", Type: "text", Label: "Grant", Required: true},
			{Name: "user", Type: "text", Label: "The person's user", Required: true},
			{Name: "kind", Type: "choice", Label: "What for", Required: true, Options: []string{kindAdmin, kindTunnel}},
			{Name: "key", Type: "text", Label: "The person's public key", Required: true},
			{Name: "expires", Type: "text", Label: "Until, YYYYMMDDHHMM UTC", Required: true},
			{Name: "port", Type: "text", Label: "Port on the server's 127.0.0.1 (tunnel)"},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			key, blob, port, until, err := grantInputs(in, time.Now().UTC())
			if err != nil {
				return nil, nil, err
			}
			name, grant, kind := in["user"], in["grant"], in["kind"]
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Let " + name + " in", Run: func(c *steps.Context) error {
				u, err := ensureAccessUser(name, kind)
				if err != nil {
					return err
				}
				body, _, admins := withGrant(readAuthorizedKeys(u), grant, grantLine(kind, key, blob, grant, until, port))
				if err := allowSudo(name, admins > 0); err != nil {
					return err
				}
				if err := writeAuthorizedKeys(u, body); err != nil {
					return err
				}
				if err := steps.AllowAccessUser(name, true); err != nil {
					return err
				}
				c.Result = map[string]any{"user": name, "grant": grant, "kind": kind, "fingerprint": key.Fingerprint}
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "access-revoke",
		Title:       "Take a person's way in away",
		Description: "Takes a grant's key line away; with no admin grant left the user loses sudo, with no grant left it is logged out, leaves AllowUsers if forge put it there and is removed if forge made it. A grant already gone isn't an error.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "grant", Type: "text", Label: "Grant", Required: true},
			{Name: "user", Type: "text", Label: "The person's user", Required: true},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			if !grantIDRe.MatchString(in["grant"]) {
				return nil, nil, errors.New("grant: a-z, 0-9 and -, up to 40")
			}
			name, grant := in["user"], in["grant"]
			if err := grantUser(name); err != nil {
				return nil, nil, err
			}
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Take " + name + "'s way in away", Run: func(c *steps.Context) error {
				c.Result = map[string]any{"user": name, "grant": grant, "removed": false}
				known, listed := steps.FindAccessUser(name)
				u, err := user.Lookup(name)
				if err != nil || !listed {
					return nil
				}
				body, left, admins := withGrant(readAuthorizedKeys(u), grant, "")
				if err := writeAuthorizedKeys(u, body); err != nil {
					return err
				}
				if err := allowSudo(name, admins > 0); err != nil {
					return err
				}
				if left > 0 {
					return nil
				}
				// Open sessions end with the grant: a shell or a tunnel already up would otherwise outlive it. An adopted
				// user with keys of its own keeps its sessions: those may not be the grant's.
				if !known.Adopted || strings.TrimSpace(body) == "" {
					_, _ = system.Run("loginctl", "terminate-user", name)
					_, _ = system.Run("pkill", "-KILL", "-u", name)
				}
				if known.Allowed {
					if err := steps.AllowAccessUser(name, false); err != nil {
						return err
					}
				}
				if !known.Adopted {
					if _, err := system.Run("userdel", "-r", name); err != nil {
						return err
					}
					c.Result["removed"] = true
				}
				return steps.SetAccessUser(known, false)
			}}}, ctx, nil
		},
	},
}

func init() {
	modules = append(modules, grantModules...)
}
