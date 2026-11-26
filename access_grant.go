package main

// A person's own way in, with a term (the module's access grants):
//
//	access-grant   a personal user s-<id> (made if missing, no shell, no
//	               password) and one line in its authorized_keys: the key,
//	               what it may do and until when sshd lets it in
//	               (expiry-time), signed studio-os:<grant>
//	access-revoke  takes that line away; a user left with none is logged
//	               out, taken off AllowUsers and removed
//
// Only users forge made for grants (steps.AccessUsersFile) are ever touched:
// never root, the deploy user or anyone the server had before.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

var (
	grantIDRe    = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	accessUserRe = regexp.MustCompile(`^s-[0-9]{1,12}$`)
	expiresRe    = regexp.MustCompile(`^[0-9]{12}$`)
)

// grantMarker ends each authorized_keys line a grant adds.
func grantMarker(grant string) string { return "studio-os:" + grant }

// grantLine is the authorized_keys line of a tunnel grant: no shell, no pty,
// only a forward to one port on the server's loopback, until the moment given.
// sshd reads expiry-time in the server's own time zone (a trailing Z isn't
// known to every OpenSSH a server may have).
func grantLine(key accessKey, blob, grant string, until time.Time, port int) string {
	return fmt.Sprintf(`restrict,port-forwarding,permitopen="127.0.0.1:%d",expiry-time="%s" %s %s %s`,
		port, until.In(time.Local).Format("200601021504"), key.Type, blob, grantMarker(grant))
}

// withGrant is authorized_keys with the grant's line put in (in place of an
// earlier one of the same grant) or, with line "", taken out; and how many
// grant lines are left.
func withGrant(content, grant, line string) (string, int) {
	var kept []string
	left := 0
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if l == "" {
			continue
		}
		if strings.HasSuffix(l, " "+grantMarker(grant)) {
			continue
		}
		if strings.Contains(l, " studio-os:") {
			left++
		}
		kept = append(kept, l)
	}
	if line != "" {
		kept = append(kept, line)
		left++
	}
	body := strings.Join(kept, "\n")
	if body != "" {
		body += "\n"
	}
	return body, left
}

// grantInputs checks access-grant's inputs: the key, its base64, the port and
// the moment the grant ends.
func grantInputs(in map[string]string, now time.Time) (accessKey, string, int, time.Time, error) {
	var zero time.Time
	if !grantIDRe.MatchString(in["grant"]) {
		return accessKey{}, "", 0, zero, errors.New("grant: a-z, 0-9 and -, up to 40")
	}
	if !accessUserRe.MatchString(in["user"]) {
		return accessKey{}, "", 0, zero, errors.New("user: s-<digits>, a personal user forge makes for grants")
	}
	if in["kind"] != "tunnel" {
		return accessKey{}, "", 0, zero, errors.New("kind: tunnel")
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
	port, err := strconv.Atoi(in["port"])
	if err != nil || port < 1 || port > 65535 {
		return accessKey{}, "", 0, zero, errors.New("port: 1-65535")
	}
	return key, blob, port, until, nil
}

// ensureAccessUser makes the personal user unless forge made it already; a
// user by that name forge didn't make is refused.
func ensureAccessUser(name string) (*user.User, error) {
	if u, err := user.Lookup(name); err == nil {
		if !slices.Contains(steps.AccessUsers(), name) {
			return nil, fmt.Errorf("%s is on this server already and forge didn't make it: refused", name)
		}
		return u, nil
	}
	if _, err := system.Run("groupadd", "-f", "forge-access"); err != nil {
		return nil, err
	}
	if _, err := system.Run("useradd", "-m", "-s", "/usr/sbin/nologin", "-G", "forge-access", "-c", "Studio OS access", name); err != nil {
		return nil, err
	}
	// "*": no password to sign in with, and not "locked" (a "!" would keep sshd from letting the key in).
	if _, err := system.Run("usermod", "-p", "*", name); err != nil {
		return nil, err
	}
	if err := steps.SetAccessUser(name, true); err != nil {
		return nil, err
	}
	return user.Lookup(name)
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
		Description: "A personal user s-<id> (made if missing: no shell, no password) gets one key line with what it may do and until when sshd lets it in (expiry-time), signed studio-os:<grant>; through forge's AllowUsers too. The same grant again replaces its line.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "grant", Type: "text", Label: "Grant", Required: true},
			{Name: "user", Type: "text", Label: "Personal user, s-<id>", Required: true},
			{Name: "kind", Type: "choice", Label: "What for", Required: true, Options: []string{"tunnel"}},
			{Name: "key", Type: "text", Label: "The person's public key", Required: true},
			{Name: "expires", Type: "text", Label: "Until, YYYYMMDDHHMM UTC", Required: true},
			{Name: "port", Type: "text", Label: "Port on the server's 127.0.0.1", Required: true},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			key, blob, port, until, err := grantInputs(in, time.Now().UTC())
			if err != nil {
				return nil, nil, err
			}
			name, grant := in["user"], in["grant"]
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Let " + name + " in", Run: func(c *steps.Context) error {
				u, err := ensureAccessUser(name)
				if err != nil {
					return err
				}
				body, _ := withGrant(readAuthorizedKeys(u), grant, grantLine(key, blob, grant, until, port))
				if err := writeAuthorizedKeys(u, body); err != nil {
					return err
				}
				if err := steps.AllowAccessUser(name, true); err != nil {
					return err
				}
				c.Result = map[string]any{"user": name, "grant": grant, "fingerprint": key.Fingerprint}
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "access-revoke",
		Title:       "Take a person's way in away",
		Description: "Takes a grant's key line away; a personal user left with none is logged out, taken off AllowUsers and removed. A grant already gone isn't an error.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "grant", Type: "text", Label: "Grant", Required: true},
			{Name: "user", Type: "text", Label: "Personal user, s-<id>", Required: true},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			if !grantIDRe.MatchString(in["grant"]) {
				return nil, nil, errors.New("grant: a-z, 0-9 and -, up to 40")
			}
			name, grant := in["user"], in["grant"]
			if !accessUserRe.MatchString(name) {
				return nil, nil, errors.New("user: s-<digits>")
			}
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Take " + name + "'s way in away", Run: func(c *steps.Context) error {
				c.Result = map[string]any{"user": name, "grant": grant, "removed": false}
				u, err := user.Lookup(name)
				if err != nil || !slices.Contains(steps.AccessUsers(), name) {
					return nil
				}
				body, left := withGrant(readAuthorizedKeys(u), grant, "")
				if err := writeAuthorizedKeys(u, body); err != nil {
					return err
				}
				if left > 0 {
					return nil
				}
				// Open sessions end with the user: a tunnel already up would otherwise outlive the grant.
				_, _ = system.Run("loginctl", "terminate-user", name)
				_, _ = system.Run("pkill", "-KILL", "-u", name)
				if err := steps.AllowAccessUser(name, false); err != nil {
					return err
				}
				if _, err := system.Run("userdel", "-r", name); err != nil {
					return err
				}
				c.Result["removed"] = true
				return steps.SetAccessUser(name, false)
			}}}, ctx, nil
		},
	},
}

func init() {
	modules = append(modules, grantModules...)
}
