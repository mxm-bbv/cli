package main

// Who can sign in to the server, and the two things a program changes about it
// when a server starts a new life: a key someone left in a user's
// authorized_keys, and the server's own host keys.
//
//	access-list   every user with an authorized_keys file: groups, and each
//	              key's fingerprint, comment and options (read only)
//	access-drop   takes keys out of one user's authorized_keys by fingerprint;
//	              never the key a program said it signs in with
//	host-keys     makes the server's host keys again and hands back the new
//	              public halves

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
)

// accessKey is one line of an authorized_keys file.
type accessKey struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment"`
	Options     string `json:"options"`
}

// accessUser is a user someone can sign in as with a key.
type accessUser struct {
	User   string      `json:"user"`
	UID    int         `json:"uid"`
	Home   string      `json:"home"`
	Shell  string      `json:"shell"`
	Groups []string    `json:"groups"`
	Keys   []accessKey `json:"keys"`
}

// parseAuthorizedKey reads one authorized_keys line: options, the key, its
// comment. The key is the field whose next field is a key blob of that very
// type, so an option can't pass for one.
func parseAuthorizedKey(line string) (accessKey, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return accessKey{}, false
	}
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		blob, err := base64.StdEncoding.DecodeString(f[i+1])
		if err != nil || len(blob) < 4 {
			continue
		}
		n := binary.BigEndian.Uint32(blob)
		if n == 0 || int(n) > len(blob)-4 || string(blob[4:4+n]) != f[i] {
			continue
		}
		sum := sha256.Sum256(blob)
		return accessKey{
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
			Type:        f[i],
			Comment:     strings.Join(f[i+2:], " "),
			Options:     strings.Join(f[:i], " "),
		}, true
	}
	return accessKey{}, false
}

// passwdEntry is one line of /etc/passwd.
type passwdEntry struct {
	name, home, shell string
	uid               int
}

func readPasswd(path string) ([]passwdEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []passwdEntry
	for _, l := range strings.Split(string(data), "\n") {
		p := strings.Split(l, ":")
		if len(p) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil {
			continue
		}
		out = append(out, passwdEntry{name: p[0], uid: uid, home: p[5], shell: p[6]})
	}
	return out, nil
}

// accessList is every user whose home has an authorized_keys file, root first.
func accessList(passwd string, groupsOf func(string) []string) ([]accessUser, error) {
	entries, err := readPasswd(passwd)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []accessUser
	for _, e := range entries {
		if e.home == "" || seen[e.home] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.home, ".ssh", "authorized_keys"))
		if err != nil {
			continue
		}
		seen[e.home] = true
		u := accessUser{User: e.name, UID: e.uid, Home: e.home, Shell: e.shell, Groups: groupsOf(e.name), Keys: []accessKey{}}
		for _, l := range strings.Split(string(data), "\n") {
			if k, ok := parseAuthorizedKey(l); ok {
				u.Keys = append(u.Keys, k)
			}
		}
		out = append(out, u)
	}
	slices.SortStableFunc(out, func(a, b accessUser) int {
		if (a.UID == 0) != (b.UID == 0) {
			if a.UID == 0 {
				return -1
			}
			return 1
		}
		return strings.Compare(a.User, b.User)
	})
	return out, nil
}

func groupsOf(name string) []string {
	u, err := user.Lookup(name)
	if err != nil {
		return []string{}
	}
	ids, err := u.GroupIds()
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			out = append(out, g.Name)
		}
	}
	return out
}

var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// fingerprints reads a list of key fingerprints, one per line or space.
func fingerprints(s string) ([]string, error) {
	var out []string
	for _, f := range strings.Fields(s) {
		if !fingerprintRe.MatchString(f) {
			return nil, fmt.Errorf("not a key fingerprint: %q (SHA256:…)", f)
		}
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out, nil
}

// dropKeys is authorized_keys without the keys in drop. keep is a key that
// must stay: dropping it, or a file without it, is refused. A file left with
// no key at all is refused for the user forge works for (lock), since that is
// how a program signs in.
func dropKeys(content string, drop []string, keep string, lock bool) (string, []string, error) {
	if keep != "" && slices.Contains(drop, keep) {
		return "", nil, errors.New("that is the key the module signs in with: it stays")
	}
	var kept, removed []string
	keys, hasKeep := 0, false
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		k, ok := parseAuthorizedKey(l)
		if ok && slices.Contains(drop, k.Fingerprint) {
			if !slices.Contains(removed, k.Fingerprint) {
				removed = append(removed, k.Fingerprint)
			}
			continue
		}
		if ok {
			keys++
			hasKeep = hasKeep || k.Fingerprint == keep
		}
		if l != "" || len(kept) > 0 {
			kept = append(kept, l)
		}
	}
	if keep != "" && !hasKeep {
		return "", nil, errors.New("the module's key isn't in this authorized_keys: nothing removed")
	}
	if lock && keys == 0 && len(removed) > 0 {
		return "", nil, errors.New("that would leave no key to sign in with: nothing removed")
	}
	body := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if body != "" {
		body += "\n"
	}
	return body, removed, nil
}

// accessDrop takes keys out of a user's authorized_keys. The file as it was
// goes to /var/lib/forge/access first; the new one keeps its owner and 0600.
func accessDrop(u *user.User, drop []string, keep string, lock bool, backupDir string) (removed, missing []string, err error) {
	path := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has no authorized_keys: %w", u.Username, err)
	}
	body, removed, err := dropKeys(string(data), drop, keep, lock)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range drop {
		if !slices.Contains(removed, f) {
			missing = append(missing, f)
		}
	}
	if len(removed) == 0 {
		return removed, missing, nil
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, nil, err
	}
	bak := filepath.Join(backupDir, u.Username+"-"+time.Now().UTC().Format("20060102-150405")+".authorized_keys")
	if err := os.WriteFile(bak, data, 0o600); err != nil {
		return nil, nil, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	tmp := path + ".forge-access"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		os.Remove(tmp)
		return nil, nil, err
	}
	return removed, missing, os.Rename(tmp, path)
}

var accessModules = []module{
	{
		Name:        "access-list",
		Title:       "Who can sign in",
		Description: "Every user with an authorized_keys file: their groups, and each key's fingerprint, comment and options. Nothing changes.",
		Internal:    true,
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Read who can sign in", Run: func(c *steps.Context) error {
				users, err := accessList("/etc/passwd", groupsOf)
				if err != nil {
					return err
				}
				if users == nil {
					users = []accessUser{}
				}
				c.Result = map[string]any{"users": users}
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "access-drop",
		Title:       "Take keys away",
		Description: "Takes keys out of one user's authorized_keys by fingerprint; the file as it was is kept in /var/lib/forge/access. Never the key the module signs in with, and never the last key of the user forge works for.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "user", Type: "text", Label: "User", Required: true},
			{Name: "fingerprints", Type: "text", Label: "Keys to take away, SHA256:… one per line", Required: true},
			{Name: "keep", Type: "text", Label: "The module's key, SHA256:…", Help: "refused if it's among them or not in the file"},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			if err := config.ValidUsername(in["user"]); err != nil && in["user"] != "root" {
				return nil, nil, fmt.Errorf("user: %w", err)
			}
			u, err := user.Lookup(in["user"])
			if err != nil {
				return nil, nil, fmt.Errorf("no user %s here", in["user"])
			}
			drop, err := fingerprints(in["fingerprints"])
			if err != nil {
				return nil, nil, err
			}
			if len(drop) == 0 {
				return nil, nil, errors.New("fingerprints: name at least one key")
			}
			keep := in["keep"]
			if keep != "" && !fingerprintRe.MatchString(keep) {
				return nil, nil, fmt.Errorf("keep: not a key fingerprint: %q", keep)
			}
			lock := u.Uid == strconv.Itoa(sudoUID()) || u.Username == os.Getenv("SUDO_USER")
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Take keys away from " + u.Username, Run: func(c *steps.Context) error {
				removed, missing, err := accessDrop(u, drop, keep, lock, "/var/lib/forge/access")
				if err != nil {
					return err
				}
				if removed == nil {
					removed = []string{}
				}
				if missing == nil {
					missing = []string{}
				}
				c.Result = map[string]any{"user": u.Username, "removed": removed, "missing": missing}
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "host-keys",
		Title:       "New host keys",
		Description: "Makes the server's host keys again, the same types, and has sshd take them: open sessions stay, the next one meets the new keys. Hands back their public halves; the old ones are kept in /var/lib/forge/host-keys.",
		Danger:      true,
		Internal:    true,
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Make new host keys", Run: func(c *steps.Context) error {
				keys, err := steps.RenewHostKeys()
				if err != nil {
					return err
				}
				c.Result = map[string]any{"keys": keys}
				return nil
			}}}, ctx, nil
		},
	},
}

func init() {
	modules = append(modules, accessModules...)
}
