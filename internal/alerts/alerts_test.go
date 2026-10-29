package alerts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeServer points the package at a temporary alerts.env and state folder,
// records what would reach Telegram, and lets the test move the clock.
type fakeServer struct {
	sent  []string
	clock time.Time
}

func newServer(t *testing.T, env string) *fakeServer {
	t.Helper()
	dir := t.TempDir()
	s := &fakeServer{clock: time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC)}
	prevEnv, prevState, prevTransport, prevNow, prevHost := EnvPath, StateDir, transport, now, hostname
	EnvPath, StateDir = filepath.Join(dir, "alerts.env"), filepath.Join(dir, "state")
	transport = func(msg string) error { s.sent = append(s.sent, msg); return nil }
	now = func() time.Time { return s.clock }
	hostname = func() string { return "votonya" }
	t.Cleanup(func() {
		EnvPath, StateDir, transport, now, hostname = prevEnv, prevState, prevTransport, prevNow, prevHost
	})
	if env != "" {
		if err := os.WriteFile(EnvPath, []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s *fakeServer) wait(d time.Duration) { s.clock = s.clock.Add(d) }

const bot = "TELEGRAM_BOT_TOKEN=123456789:AAexampleexampleexampleexampleexample\nTELEGRAM_CHAT_ID=42\n"

func TestParseEnvReadsQuotedValues(t *testing.T) {
	vals := ParseEnv("# managed\nALERT_NAME='Votonia VPS'\nALERT_SSH_LOGIN=new\n\nALERT_QUIET_FROM='203.0.113.7/32 100.64.0.0/10'\n")
	if vals["ALERT_NAME"] != "Votonia VPS" || vals["ALERT_SSH_LOGIN"] != "new" || vals["ALERT_QUIET_FROM"] != "203.0.113.7/32 100.64.0.0/10" {
		t.Fatalf("parsed %v", vals)
	}
}

func TestLoginModeKeepsOldFilesQuiet(t *testing.T) {
	for in, want := range map[string]string{"1": LoginsNew, "0": LoginsOff, "": LoginsOff, "new": LoginsNew, "all": LoginsAll, "off": LoginsOff, "yes": LoginsOff} {
		if got := LoginMode(in); got != want {
			t.Errorf("LoginMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseQuiet(t *testing.T) {
	got, err := ParseQuiet("203.0.113.7, 100.64.0.0/10 2001:db8::1 ::ffff:198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if strings.Join(s, " ") != "203.0.113.7/32 100.64.0.0/10 2001:db8::1/128 198.51.100.1/32" {
		t.Fatalf("got %v", s)
	}
	for _, bad := range []string{"example.com", "1.2.3.4/33", "'; rm -rf /", "$(id)"} {
		if _, err := ParseQuiet(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNothingIsSentWithoutABot(t *testing.T) {
	s := newServer(t, "")
	if err := Send(Alert{Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := Login("deploy", "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if len(s.sent) != 0 {
		t.Fatalf("sent %v", s.sent)
	}
}

func TestEveryMessageNamesTheServer(t *testing.T) {
	s := newServer(t, bot+"ALERT_NAME='Votonia'\n")
	_ = Send(Alert{Text: "⚠️ root filesystem 91% full"})
	if len(s.sent) != 1 || s.sent[0] != "Votonia · ⚠️ root filesystem 91% full" {
		t.Fatalf("sent %q", s.sent)
	}

	s = newServer(t, bot)
	_ = Send(Alert{Text: "hi"})
	if s.sent[0] != "votonya · hi" {
		t.Fatalf("without a name the hostname says which server: %q", s.sent[0])
	}
}

func TestAKeyGoesOutOnceWithinItsPause(t *testing.T) {
	s := newServer(t, bot)
	disk := Alert{Text: "disk", Key: "disk", Every: 6 * time.Hour}
	_ = Send(disk)
	s.wait(15 * time.Minute)
	_ = Send(disk)
	s.wait(6 * time.Hour)
	_ = Send(disk)
	if len(s.sent) != 2 {
		t.Fatalf("sent %d, want 2: %v", len(s.sent), s.sent)
	}
}

// What spammed on votonia-kz: every connection deploy.me opened was a message.
func TestLoginsFromTheSameAddressAreSaidOnceADay(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=1\n")
	for i := 0; i < 11; i++ {
		_ = Login("deploy", "2.135.53.39")
		s.wait(2 * time.Minute)
	}
	if len(s.sent) != 1 || !strings.Contains(s.sent[0], "🔐 SSH login: deploy from 2.135.53.39") {
		t.Fatalf("sent %v", s.sent)
	}

	_ = Login("deploy", "198.51.100.9") // another address is news
	_ = Login("admin", "2.135.53.39")   // so is another user
	if len(s.sent) != 3 {
		t.Fatalf("sent %d, want 3: %v", len(s.sent), s.sent)
	}

	s.wait(24 * time.Hour)
	_ = Login("deploy", "2.135.53.39")
	if len(s.sent) != 4 {
		t.Fatalf("a day later the address is said again: %v", s.sent)
	}
}

func TestRootIsSaidEveryHour(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=new\n")
	_ = Login("root", "198.51.100.9")
	s.wait(30 * time.Minute)
	_ = Login("root", "198.51.100.9")
	s.wait(31 * time.Minute)
	_ = Login("root", "198.51.100.9")
	if len(s.sent) != 2 {
		t.Fatalf("sent %v", s.sent)
	}
}

func TestEveryLoginAndNone(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=all\n")
	_ = Login("deploy", "203.0.113.7")
	_ = Login("deploy", "203.0.113.7")
	if len(s.sent) != 2 || strings.Contains(s.sent[0], "summary") {
		t.Fatalf("all: %v", s.sent)
	}

	s = newServer(t, bot+"ALERT_SSH_LOGIN=off\n")
	_ = Login("root", "203.0.113.7")
	if len(s.sent) != 0 {
		t.Fatalf("off: %v", s.sent)
	}
}

func TestQuietAddressesOnlyCountInTheSummary(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=new\nALERT_QUIET_FROM='2.135.53.39 100.64.0.0/10'\n")
	_ = Digest() // the summary's day starts now
	for i := 0; i < 37; i++ {
		_ = Login("deploy", "2.135.53.39")
	}
	_ = Login("deploy", "100.101.102.103")
	_ = Login("deploy", "::ffff:2.135.53.39")
	if len(s.sent) != 0 {
		t.Fatalf("quiet logins sent: %v", s.sent)
	}

	s.wait(12 * time.Hour)
	_ = Digest()
	if len(s.sent) != 0 {
		t.Fatal("the summary waits for its day")
	}
	s.wait(12 * time.Hour)
	_ = Digest()
	if len(s.sent) != 1 {
		t.Fatalf("sent %v", s.sent)
	}
	msg := s.sent[0]
	for _, want := range []string{"votonya · 📋 Last 24 hours", "• deploy from 2.135.53.39 (quiet address): 37 logins", "• deploy from 100.101.102.103 (quiet address): 1 login", "• deploy from ::ffff:2.135.53.39 (quiet address): 1 login"} {
		if !strings.Contains(msg, want) {
			t.Errorf("summary lacks %q:\n%s", want, msg)
		}
	}

	s.wait(24 * time.Hour)
	_ = Digest()
	if len(s.sent) != 1 {
		t.Fatalf("a day with nothing to say sends nothing: %v", s.sent)
	}
}

func TestRepeatsAndHeldMessagesReachTheSummary(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=new\nALERT_MAX_PER_HOUR=3\n")
	_ = Digest()
	for i := 0; i < 5; i++ {
		_ = Login("deploy", "203.0.113.7")
	}
	for i := 0; i < 5; i++ {
		_ = Send(Alert{Text: "tripwire " + string(rune('a'+i)) + "\ndetails"})
	}
	// 1 login + 2 tripwire messages reach the limit of 3; the 4th says so once.
	if len(s.sent) != 4 || !strings.Contains(s.sent[3], "⏸ More than 3 alerts in an hour") {
		t.Fatalf("sent %v", s.sent)
	}

	s.wait(24 * time.Hour)
	_ = Digest()
	summary := s.sent[len(s.sent)-1]
	for _, want := range []string{"• deploy from 203.0.113.7: 4 more logins", "• 3 alerts over the hourly limit, the first: tripwire c; tripwire d; tripwire e"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}

	_ = Send(Alert{Text: "after an hour the limit is free again"})
	if !strings.HasSuffix(s.sent[len(s.sent)-1], "after an hour the limit is free again") {
		t.Fatalf("sent %v", s.sent)
	}
}

func TestAFailedSendIsTriedAgain(t *testing.T) {
	s := newServer(t, bot)
	transport = func(string) error { return os.ErrDeadlineExceeded }
	disk := Alert{Text: "disk", Key: "disk", Every: 6 * time.Hour}
	if err := Send(disk); err == nil {
		t.Fatal("the error should come back")
	}
	transport = func(msg string) error { s.sent = append(s.sent, msg); return nil }
	_ = Send(disk)
	if len(s.sent) != 1 {
		t.Fatalf("the pause began without a message: %v", s.sent)
	}
}

// A flood of logins from new addresses fills the hour; the tripwire still
// gets through.
func TestUrgentAlertsPassTheHourlyLimit(t *testing.T) {
	s := newServer(t, bot+"ALERT_SSH_LOGIN=new\nALERT_MAX_PER_HOUR=2\n")
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		_ = Login("deploy", ip)
	}
	_ = Send(Alert{Text: "🚨 Changes of the kind intruders make", Urgent: true})
	if last := s.sent[len(s.sent)-1]; !strings.Contains(last, "🚨 Changes") {
		t.Fatalf("the tripwire was held back: %v", s.sent)
	}
}
