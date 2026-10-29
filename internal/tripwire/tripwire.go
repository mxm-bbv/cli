// Package tripwire watches what an intruder changes to stay on a box — SSH
// keys, accounts, sudo rights, sshd policy, listening ports, services, cron,
// startup files, SUID binaries, kernel taint and container images — and
// reports every difference from the last known state to Telegram.
//
// `forge tripwire` runs every minute from a systemd timer. The daily `forge
// audit` looks for known compromise patterns; this catches the change itself,
// minutes after it happens, whatever it is. Each change is reported once: the
// new state becomes the baseline.
package tripwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mxm-bbv/cli/internal/alerts"
)

// Snapshot maps a category to its sorted entries.
type Snapshot map[string][]string

type state struct {
	Taken  time.Time `json:"taken"`
	SUIDAt time.Time `json:"suid_at"`
	Items  Snapshot  `json:"items"`
}

// Seams for tests.
var (
	Root      = "/"
	StatePath = "/var/lib/forge/tripwire.json"
	notify    = func(msg string) error { return alerts.Send(alerts.Alert{Text: msg, Urgent: true}) }
	output    = func(name string, args ...string) string {
		out, _ := exec.Command(name, args...).Output()
		return string(out)
	}
	now = time.Now
)

// suidEvery spaces out the full-filesystem SUID scan; the rest is cheap.
const suidEvery = 15 * time.Minute

// labels name the categories in reports, in report order.
var labels = []struct{ key, label string }{
	{"ssh-keys", "SSH key"},
	{"sshd", "sshd setting"},
	{"accounts", "account"},
	{"groups", "privileged group"},
	{"sudoers", "sudo rules"},
	{"listeners", "listening port"},
	{"units", "systemd unit"},
	{"cron", "cron job"},
	{"startup", "startup file"},
	{"suid", "SUID/SGID file"},
	{"kernel", "kernel"},
	{"containers", "container image"},
}

// Installed reports whether a baseline exists, i.e. the tripwire is active.
func Installed() bool {
	_, err := os.Stat(StatePath)
	return err == nil
}

// Run takes a snapshot and reports what changed since the baseline. With
// baseline=true (after forge itself changed the box) it only records the
// current state. It returns a process exit code.
func Run(baseline bool) int {
	prev, havePrev := load()
	cur := take(prev)
	if !havePrev || baseline {
		return saveOrFail(cur)
	}
	changes := Diff(prev.Items, cur.Items)
	if len(changes) == 0 {
		return saveOrFail(cur)
	}
	if err := notify(Report(changes)); err != nil {
		// Keep the old baseline: the next run retries the alert.
		fmt.Fprintln(os.Stderr, "tripwire: alert not sent:", err)
		return 1
	}
	return saveOrFail(cur)
}

// Diff lists added ("+ label: entry") and removed ("- label: entry") entries.
func Diff(old, cur Snapshot) []string {
	var out []string
	for _, l := range labels {
		o, c := old[l.key], cur[l.key]
		for _, e := range c {
			if !slices.Contains(o, e) {
				out = append(out, "+ "+l.label+": "+e)
			}
		}
		for _, e := range o {
			if !slices.Contains(c, e) {
				out = append(out, "- "+l.label+": "+e)
			}
		}
	}
	return out
}

// Report formats changes as a Telegram message (kept under its 4096 limit).
func Report(changes []string) string {
	body := strings.Join(changes, "\n")
	if len(body) > 3300 {
		body = body[:3300] + "\n… (more — see `sudo forge tripwire --show`)"
	}
	return "🚨 Changes of the kind intruders make\n\n" + body +
		"\n\nYou did this? Then ignore it — it won't be reported again.\n" +
		"Not you? Run  sudo forge audit  and consider rebuilding the server from a snapshot."
}

// Show prints the current snapshot (for `forge tripwire --show`).
func Show() {
	cur := take(state{})
	for _, l := range labels {
		for _, e := range cur.Items[l.key] {
			fmt.Println(l.label + ": " + e)
		}
	}
}

func load() (state, bool) {
	var s state
	data, err := os.ReadFile(StatePath)
	if err != nil || json.Unmarshal(data, &s) != nil || s.Items == nil {
		return state{}, false
	}
	return s, true
}

func saveOrFail(s state) int {
	data, _ := json.Marshal(s)
	if err := os.MkdirAll(filepath.Dir(StatePath), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "tripwire:", err)
		return 1
	}
	tmp := StatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "tripwire:", err)
		return 1
	}
	if err := os.Rename(tmp, StatePath); err != nil {
		fmt.Fprintln(os.Stderr, "tripwire:", err)
		return 1
	}
	return 0
}

// take collects a snapshot, reusing prev's SUID list until a rescan is due.
func take(prev state) state {
	t := now()
	s := state{Taken: t, SUIDAt: prev.SUIDAt, Items: Snapshot{}}
	users := passwd()
	s.Items["ssh-keys"] = sshKeys(users)
	s.Items["sshd"] = sshdPolicy()
	s.Items["accounts"] = accounts(users)
	s.Items["groups"] = privilegedGroups()
	s.Items["sudoers"] = hashed("/etc/sudoers", "/etc/sudoers.d/*")
	s.Items["listeners"] = listeners()
	s.Items["units"] = units(users)
	s.Items["cron"] = hashed("/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*")
	s.Items["startup"] = startup(users)
	s.Items["kernel"] = kernel()
	s.Items["containers"] = containers()
	if prev.Items != nil && t.Sub(prev.SUIDAt) < suidEvery {
		s.Items["suid"] = prev.Items["suid"]
	} else {
		s.Items["suid"], s.SUIDAt = suid(), t
	}
	for k := range s.Items {
		slices.Sort(s.Items[k])
		s.Items[k] = slices.Compact(s.Items[k])
	}
	return s
}

func path(p string) string { return filepath.Join(Root, p) }

type user struct {
	name, home, shell string
	uid               int
}

func passwd() []user {
	data, _ := os.ReadFile(path("/etc/passwd"))
	var us []user
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		us = append(us, user{name: f[0], uid: uid, home: f[5], shell: f[6]})
	}
	return us
}

// loginShell: an account someone can log in to interactively.
func (u user) loginShell() bool {
	base := filepath.Base(u.shell)
	return u.shell != "" && base != "nologin" && base != "false" && base != "sync" &&
		base != "halt" && base != "shutdown"
}

func accounts(us []user) []string {
	var out []string
	for _, u := range us {
		if u.uid == 0 || u.loginShell() {
			out = append(out, fmt.Sprintf("%s uid=%d shell=%s", u.name, u.uid, u.shell))
		}
	}
	return out
}

func sshKeys(us []user) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range us {
		if u.home == "" || seen[u.home] {
			continue
		}
		seen[u.home] = true
		for _, f := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			data, err := os.ReadFile(path(filepath.Join(u.home, f)))
			if err != nil {
				continue
			}
			out = append(out, parseKeys(u.name, data)...)
		}
	}
	return out
}

// parseKeys describes each authorized_keys entry by fingerprint, comment and
// options (an added command="…" or from="…" matters as much as a new key).
func parseKeys(owner string, data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			out = append(out, owner+": unparsable entry "+short(line))
			continue
		}
		e := owner + ": " + pub.Type() + " " + ssh.FingerprintSHA256(pub)
		if comment != "" {
			e += " " + comment
		}
		if len(opts) > 0 {
			e += " [" + strings.Join(opts, ",") + "]"
		}
		out = append(out, e)
	}
	return out
}

var sshdKeys = []string{"port", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
	"pubkeyauthentication", "permitemptypasswords", "authorizedkeysfile", "authorizedkeyscommand",
	"authorizedkeyscommanduser", "allowusers", "allowgroups"}

func sshdPolicy() []string {
	var out []string
	for _, line := range strings.Split(output("sshd", "-T"), "\n") {
		k, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		if slices.Contains(sshdKeys, k) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func privilegedGroups() []string {
	data, _ := os.ReadFile(path("/etc/group"))
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		switch f[0] {
		case "root", "sudo", "admin", "wheel", "docker":
			if f[3] != "" {
				out = append(out, f[0]+": "+f[3])
			}
		}
	}
	return out
}

// listeners: TCP/UDP sockets reachable from outside the box. Loopback is
// local-only, and tailscaled picks new ports on every restart.
func listeners() []string {
	var out []string
	for _, line := range strings.Split(output("ss", "-H", "-l", "-t", "-u", "-n", "-p"), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		if strings.HasPrefix(local, "127.") || strings.HasPrefix(local, "[::1]") || strings.HasPrefix(local, "::1") ||
			strings.Contains(local, "%lo:") {
			continue
		}
		proc := "?"
		if i := strings.Index(line, `(("`); i >= 0 {
			proc, _, _ = strings.Cut(line[i+3:], `"`)
		}
		if proc == "tailscaled" {
			continue
		}
		out = append(out, f[0]+" "+local+" ("+proc+")")
	}
	return out
}

func units(us []user) []string {
	var out []string
	// /etc/systemd/system in full: an enabled unit shows up as a new
	// *.wants/ link, which is the persistence step itself.
	root := path("/etc/systemd/system")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, "/etc/systemd/system/"+strings.TrimPrefix(p, root+"/"))
		}
		return nil
	})
	dirs := []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/usr/local/lib/systemd/system"}
	for _, u := range us {
		if u.home != "" {
			dirs = append(dirs, filepath.Join(u.home, ".config/systemd/user"))
		}
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		// /lib is /usr/lib on merged-/usr systems: list each directory once.
		real, err := filepath.EvalSymlinks(path(d))
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		entries, err := os.ReadDir(real)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				out = append(out, filepath.Join(d, e.Name()))
			}
		}
	}
	return out
}

// startup: files that run code at boot, login or for every process.
func startup(us []user) []string {
	globs := []string{"/etc/ld.so.preload", "/etc/rc.local", "/etc/profile", "/etc/profile.d/*",
		"/etc/bash.bashrc", "/etc/environment"}
	for _, u := range us {
		if u.home != "" && (u.uid == 0 || u.loginShell()) {
			for _, f := range []string{".bashrc", ".profile", ".bash_profile", ".bash_login"} {
				globs = append(globs, filepath.Join(u.home, f))
			}
		}
	}
	return hashed(globs...)
}

// hashed describes each regular file matching globs as "path sha256-prefix".
func hashed(globs ...string) []string {
	var out []string
	for _, g := range globs {
		matches, _ := filepath.Glob(path(g))
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			out = append(out, strings.TrimPrefix(m, strings.TrimSuffix(Root, "/"))+" "+short(string(data)))
		}
	}
	return out
}

// suid lists SUID/SGID files on the root filesystem plus the usual tmpfs drop
// spots. Container layers are skipped: images carry their own SUID binaries.
func suid() []string {
	var out []string
	skip := map[string]bool{}
	for _, d := range []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/snap"} {
		skip[path(d)] = true
	}
	walk := func(top string, sameDev bool) {
		var dev uint64
		if st, err := os.Stat(top); err == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				dev = uint64(s.Dev)
			}
		}
		_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skip[p] && p != top {
					return filepath.SkipDir
				}
				if sameDev && p != top {
					if fi, err := d.Info(); err == nil {
						if s, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(s.Dev) != dev {
							return filepath.SkipDir
						}
					}
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			out = append(out, strings.TrimPrefix(p, strings.TrimSuffix(Root, "/"))+" "+fi.Mode().String())
			return nil
		})
	}
	walk(path("/"), true)
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		walk(path(d), false)
	}
	return out
}

// kernel reports the taint flags that loading a foreign module sets: an LKM
// rootkit can hide itself from /proc/modules, not the taint it caused.
func kernel() []string {
	data, err := os.ReadFile(path("/proc/sys/kernel/tainted"))
	if err != nil {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil
	}
	var out []string
	for bit, name := range map[int]string{
		12: "out-of-tree module loaded", 13: "unsigned module loaded", 15: "kernel live-patched",
	} {
		if n&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func containers() []string {
	var out []string
	for _, img := range strings.Split(output("docker", "ps", "--format", "{{.Image}}"), "\n") {
		if img = strings.TrimSpace(img); img != "" {
			out = append(out, img)
		}
	}
	return out
}

func short(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
