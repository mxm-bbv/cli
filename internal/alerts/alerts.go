// Package alerts is how forge talks to Telegram. Every message goes through
// Send, which names the server, keeps a repeat from going out again within its
// pause, holds back what goes over the hourly limit, and counts what it didn't
// send for the daily summary. SSH logins go through Login, which decides which
// of them are worth a message at all: an alert that fires on every connection
// a program makes is an alert nobody reads.
package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Seams for tests.
var (
	EnvPath   = "/etc/forge/alerts.env"
	StateDir  = "/var/lib/forge/alerts"
	transport = func(msg string) error { return exec.Command("/usr/local/lib/forge/notify.sh", msg).Run() }
	now       = time.Now
	hostname  = func() string { h, _ := os.Hostname(); return h }
)

// DefaultMaxPerHour is how many messages a server sends in an hour before the
// rest wait for the daily summary.
const DefaultMaxPerHour = 12

const (
	loginPause  = 24 * time.Hour // a user from an address: once a day
	rootPause   = time.Hour      // root is worth hearing about more often
	digestEvery = 24 * time.Hour
	keepKeys    = 48 * time.Hour
	heldShown   = 3
)

// Which SSH logins are worth a message (ALERT_SSH_LOGIN).
const (
	LoginsNew = "new" // a user's first login from an address in a day
	LoginsAll = "all" // every login
	LoginsOff = "off"
)

// Settings is what alerts.env says beyond the bot itself.
type Settings struct {
	Configured bool   // a bot token and a chat are set
	Name       string // how messages name this server; "" = its hostname
	Logins     string // new, all or off
	Quiet      []netip.Prefix
	MaxPerHour int
}

// Alert is one message.
type Alert struct {
	Text string
	// Key and Every: an alert with the same key goes out once within Every;
	// "" always goes out (still within the hourly limit).
	Key   string
	Every time.Duration
	// Login names a login the pause kept back, for the daily summary.
	Login string
	// Urgent alerts (the tripwire, audit findings) are never held back by the
	// hourly limit: otherwise a flood of logins from new addresses would push
	// the one message that matters into tomorrow's summary.
	Urgent bool
}

// ParseEnv reads alerts.env: KEY=VALUE lines, a value optionally in single
// quotes (forge writes a name or a list that way, so the shell scripts that
// source the file read it as one word).
func ParseEnv(text string) map[string]string {
	vals := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
			v = v[1 : len(v)-1]
		}
		vals[strings.TrimSpace(k)] = v
	}
	return vals
}

// ReadEnv returns alerts.env's values, or nil when the server has none (or
// the caller can't read it: it is root's alone).
func ReadEnv() map[string]string {
	data, err := os.ReadFile(EnvPath)
	if err != nil {
		return nil
	}
	return ParseEnv(string(data))
}

// LoginMode reads ALERT_SSH_LOGIN. forge before 0.6 wrote 1 for "every login",
// which is what spammed: it now means the first from an address in a day.
func LoginMode(v string) string {
	switch v {
	case LoginsNew, LoginsAll, LoginsOff:
		return v
	case "1":
		return LoginsNew
	}
	return LoginsOff
}

// ParseQuiet reads a list of IP addresses and networks (CIDR), separated by
// spaces or commas.
func ParseQuiet(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an IP address nor a network like 100.64.0.0/10", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(out) > 32 {
		return nil, errors.New("at most 32 quiet addresses")
	}
	return out, nil
}

// SettingsFrom turns alerts.env's values into Settings.
func SettingsFrom(vals map[string]string) Settings {
	s := Settings{
		Configured: vals["TELEGRAM_BOT_TOKEN"] != "" && vals["TELEGRAM_CHAT_ID"] != "",
		Name:       vals["ALERT_NAME"],
		Logins:     LoginMode(vals["ALERT_SSH_LOGIN"]),
		MaxPerHour: DefaultMaxPerHour,
	}
	if n, err := strconv.Atoi(vals["ALERT_MAX_PER_HOUR"]); err == nil && n > 0 {
		s.MaxPerHour = n
	}
	s.Quiet, _ = ParseQuiet(vals["ALERT_QUIET_FROM"])
	return s
}

// Load reads this server's Settings; ok is false when alerts aren't set up.
func Load() (Settings, bool) {
	vals := ReadEnv()
	if vals == nil {
		return Settings{}, false
	}
	return SettingsFrom(vals), true
}

func (s Settings) label() string {
	if s.Name != "" {
		return s.Name + " · "
	}
	return hostname() + " · "
}

func (s Settings) quiet(rhost string) bool {
	a, err := netip.ParseAddr(rhost)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range s.Quiet {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// state is what forge remembers between messages, in StateDir.
type state struct {
	Keys      map[string]time.Time `json:"keys"`       // key → when it last went out
	Sent      []time.Time          `json:"sent"`       // what went out in the last hour
	CapWarned time.Time            `json:"cap_warned"` // when the hourly limit was last said
	Since     time.Time            `json:"since"`      // start of the summary's period
	Quiet     map[string]int       `json:"quiet"`      // "deploy from 203.0.113.7" → logins from a quiet address
	Repeats   map[string]int       `json:"repeats"`    // the same → logins the pause kept back
	Held      int                  `json:"held"`       // messages over the hourly limit
	HeldFirst []string             `json:"held_first"` // the first of them, for the summary
}

func (st *state) prune(t time.Time) {
	if st.Keys == nil {
		st.Keys = map[string]time.Time{}
	}
	if st.Quiet == nil {
		st.Quiet = map[string]int{}
	}
	if st.Repeats == nil {
		st.Repeats = map[string]int{}
	}
	for k, at := range st.Keys {
		if t.Sub(at) > keepKeys {
			delete(st.Keys, k)
		}
	}
	recent := st.Sent[:0]
	for _, at := range st.Sent {
		if t.Sub(at) < time.Hour {
			recent = append(recent, at)
		}
	}
	st.Sent = recent
}

// locked runs fn on the state under an exclusive lock: logins arrive in
// parallel (pam_exec), and two of them must not both decide they're first.
func locked(fn func(*state, time.Time) error) error {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	path := filepath.Join(StateDir, "state.json")
	var st state
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &st) // a damaged file starts afresh
	}
	t := now()
	st.prune(t)
	ferr := fn(&st, t)

	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return ferr
}

// Send sends one alert, unless its pause or the hourly limit keeps it back.
func Send(a Alert) error {
	set, ok := Load()
	if !ok || !set.Configured {
		return nil
	}
	return locked(func(st *state, t time.Time) error { return send(st, t, set, a) })
}

func send(st *state, t time.Time, set Settings, a Alert) error {
	if a.Key != "" {
		if last, ok := st.Keys[a.Key]; ok && t.Sub(last) < a.Every {
			if a.Login != "" {
				st.Repeats[a.Login]++
			}
			return nil
		}
	}
	if !a.Urgent && len(st.Sent) >= set.MaxPerHour {
		st.Held++
		if len(st.HeldFirst) < heldShown {
			st.HeldFirst = append(st.HeldFirst, firstLine(a.Text))
		}
		if t.Sub(st.CapWarned) >= time.Hour {
			st.CapWarned = t
			return transport(set.label() + fmt.Sprintf("⏸ More than %d alerts in an hour: the rest wait for the daily summary.", set.MaxPerHour))
		}
		return nil
	}
	if err := transport(set.label() + a.Text); err != nil {
		return err // not marked as sent: the next try goes out
	}
	st.Sent = append(st.Sent, t)
	if a.Key != "" {
		st.Keys[a.Key] = t
	}
	return nil
}

// Login decides on one SSH login (pam_exec's PAM_USER and PAM_RHOST).
func Login(user, rhost string) error {
	set, ok := Load()
	if !ok || !set.Configured || set.Logins == LoginsOff {
		return nil
	}
	if user == "" {
		user = "?"
	}
	if rhost == "" {
		rhost = "?"
	}
	who := user + " from " + rhost
	if set.quiet(rhost) {
		return locked(func(st *state, _ time.Time) error {
			st.Quiet[who]++
			return nil
		})
	}
	a := Alert{Text: "🔐 SSH login: " + who}
	if set.Logins == LoginsNew {
		a.Key, a.Every, a.Login = "login:"+user+"@"+rhost, loginPause, who
		if user == "root" {
			a.Every = rootPause
		}
		a.Text += ". More logins from there today go to the daily summary."
	}
	return locked(func(st *state, t time.Time) error { return send(st, t, set, a) })
}

// Digest sends the daily summary of what wasn't sent one by one, once a day
// (forge's health timer asks every 15 minutes). A day with nothing to say
// sends nothing.
func Digest() error {
	set, ok := Load()
	if !ok || !set.Configured {
		return nil
	}
	return locked(func(st *state, t time.Time) error {
		if st.Since.IsZero() {
			st.Since = t
			return nil
		}
		if t.Sub(st.Since) < digestEvery {
			return nil
		}
		if lines := summary(st); len(lines) > 0 {
			if err := transport(set.label() + "📋 Last 24 hours, not sent one by one:\n" + strings.Join(lines, "\n")); err != nil {
				return err
			}
		}
		st.Since, st.Quiet, st.Repeats, st.Held, st.HeldFirst = t, map[string]int{}, map[string]int{}, 0, nil
		return nil
	})
}

func summary(st *state) []string {
	var lines []string
	for _, who := range byCount(st.Quiet) {
		lines = append(lines, fmt.Sprintf("• %s (quiet address): %s", who, plural(st.Quiet[who], "login", "logins")))
	}
	for _, who := range byCount(st.Repeats) {
		n := st.Repeats[who]
		lines = append(lines, fmt.Sprintf("• %s: %d more %s", who, n, noun(n, "login", "logins")))
	}
	if st.Held > 0 {
		line := fmt.Sprintf("• %s over the hourly limit", plural(st.Held, "alert", "alerts"))
		if len(st.HeldFirst) > 0 {
			line += ", the first: " + strings.Join(st.HeldFirst, "; ")
		}
		lines = append(lines, line)
	}
	return lines
}

func byCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func plural(n int, one, many string) string {
	return strconv.Itoa(n) + " " + noun(n, one, many)
}

func noun(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 120 {
		line = line[:120] + "…"
	}
	return line
}
