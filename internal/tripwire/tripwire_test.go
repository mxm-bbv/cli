package tripwire

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@laptop"

// fakeHost builds a minimal root filesystem and stubs the commands.
func fakeHost(t *testing.T) (root string, sent *[]string) {
	t.Helper()
	root = t.TempDir()
	write := func(p, body string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"deploy:x:1000:1000::/home/deploy:/bin/bash\n", 0o644)
	write("/etc/group", "root:x:0:\nsudo:x:27:deploy\ndocker:x:999:deploy\n", 0o644)
	write("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n", 0o440)
	write("/home/deploy/.ssh/authorized_keys", adminKey+"\n", 0o600)
	write("/etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n", 0o644)
	write("/etc/systemd/system/multi-user.target.wants/ssh.service", "", 0o644)
	write("/usr/bin/passwd", "elf", 0o755)
	if err := os.Chmod(filepath.Join(root, "/usr/bin/passwd"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	write("/proc/sys/kernel/tainted", "0\n", 0o644)
	write("/etc/cron.d/e2scrub_all", "10 3 * * 0 root /sbin/e2scrub_all\n", 0o644)

	listen := "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
		"tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=2,fd=3))\n" +
		"udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:((\"tailscaled\",pid=3,fd=3))\n"
	prevRoot, prevState, prevNotify, prevOutput, prevHost, prevNow := Root, StatePath, notify, output, hostname, now
	Root, StatePath = root, filepath.Join(root, "/var/lib/forge/tripwire.json")
	var msgs []string
	notify = func(m string) error { msgs = append(msgs, m); return nil }
	output = func(name string, args ...string) string {
		switch name {
		case "ss":
			return listen
		case "sshd":
			return "port 22\npermitrootlogin no\npasswordauthentication no\nx11forwarding no\n"
		case "docker":
			return "caddy:2.11.4-alpine\nportainer/agent:2.39.1\n"
		}
		return ""
	}
	hostname = func() string { return "web-01" }
	clock := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	t.Cleanup(func() {
		Root, StatePath, notify, output, hostname, now = prevRoot, prevState, prevNotify, prevOutput, prevHost, prevNow
	})
	return root, &msgs
}

func TestTripwireReportsPersistence(t *testing.T) {
	root, sent := fakeHost(t)
	if code := Run(false); code != 0 || len(*sent) != 0 {
		t.Fatalf("first run must only record a baseline, got code %d, alerts %q", code, *sent)
	}
	if Run(false); len(*sent) != 0 {
		t.Fatalf("nothing changed, nothing to report: %q", *sent)
	}

	// What an intruder does next: an SSH key for root, a cron job, a SUID
	// shell in /tmp — all plain files, so they show up at once (the SUID
	// scan is forced by moving the clock past suidEvery).
	_ = os.MkdirAll(filepath.Join(root, "/root/.ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "/root/.ssh/authorized_keys"),
		[]byte(`command="/tmp/.x" `+strings.Replace(adminKey, "admin@laptop", "x@evil", 1)+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "/etc/cron.d/sync"), []byte("* * * * * root /tmp/.x\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "/tmp"), 0o1777)
	_ = os.WriteFile(filepath.Join(root, "/tmp/.x"), []byte("sh"), 0o755)
	_ = os.Chmod(filepath.Join(root, "/tmp/.x"), 0o755|os.ModeSetuid)
	clock := now()
	now = func() time.Time { clock = clock.Add(suidEvery); return clock }

	Run(false)
	if len(*sent) != 1 {
		t.Fatalf("want one alert, got %d: %q", len(*sent), *sent)
	}
	msg := (*sent)[0]
	for _, want := range []string{
		"web-01",
		"+ SSH key: root: ssh-ed25519 SHA256:",
		"x@evil [command=\"/tmp/.x\"]",
		"+ cron job: /etc/cron.d/sync",
		"+ SUID/SGID file: /tmp/.x",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("alert lacks %q:\n%s", want, msg)
		}
	}
	if Run(false); len(*sent) != 1 {
		t.Errorf("a change is reported once, then it is the baseline: %q", *sent)
	}
}

func TestTripwireRetriesUnsentAlert(t *testing.T) {
	root, sent := fakeHost(t)
	Run(false)
	_ = os.WriteFile(filepath.Join(root, "/etc/cron.d/x"), []byte("* * * * * root id\n"), 0o644)

	notify = func(string) error { return errors.New("network down") }
	if code := Run(false); code == 0 {
		t.Error("a failed alert must fail the run")
	}
	notify = func(m string) error { *sent = append(*sent, m); return nil }
	if Run(false); len(*sent) != 1 || !strings.Contains((*sent)[0], "/etc/cron.d/x") {
		t.Errorf("the change must be reported once the alert gets through: %q", *sent)
	}
}

func TestTripwireBaselineAbsorbsOwnChanges(t *testing.T) {
	root, sent := fakeHost(t)
	Run(false)
	_ = os.WriteFile(filepath.Join(root, "/etc/systemd/system/forge-tripwire.timer"), []byte("[Timer]\n"), 0o644)
	Run(true) // forge changed the box itself
	if Run(false); len(*sent) != 0 {
		t.Errorf("forge's own changes must not alert: %q", *sent)
	}
}

func TestListenersIgnoreLoopbackAndTailscale(t *testing.T) {
	fakeHost(t)
	got := listeners()
	if len(got) != 1 || got[0] != "tcp 0.0.0.0:22 (sshd)" {
		t.Errorf("got %q", got)
	}
}
