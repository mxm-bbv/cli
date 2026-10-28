package steps

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

var (
	ubuntuNoble = system.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "24.04", Codename: "noble", UbuntuCodename: "noble", Pretty: "Ubuntu 24.04 LTS"}
	ubuntuJammy = system.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "22.04", Codename: "jammy", UbuntuCodename: "jammy", Pretty: "Ubuntu 22.04 LTS"}
	debian12    = system.OSRelease{ID: "debian", VersionID: "12", Codename: "bookworm", Pretty: "Debian GNU/Linux 12 (bookworm)"}
	debian13    = system.OSRelease{ID: "debian", VersionID: "13", Codename: "trixie", Pretty: "Debian GNU/Linux 13 (trixie)"}
	mint22      = system.OSRelease{ID: "linuxmint", IDLike: "ubuntu debian", VersionID: "22", Codename: "wilma", UbuntuCodename: "noble", Pretty: "Linux Mint 22"}
	lmde6       = system.OSRelease{ID: "linuxmint", IDLike: "debian", VersionID: "6", Codename: "faye", DebianCodename: "bookworm", Pretty: "LMDE 6"}
)

// stockSSHDConfig is the head of Ubuntu's/Debian's packaged sshd_config.
const stockSSHDConfig = `Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
`

// dryRunAs puts the steps in dry-run mode "as" the given distro, with sshd
// config paths pointing at a temp fixture so results don't depend on the host
// running the tests.
func dryRunAs(t *testing.T, rel system.OSRelease, socket bool) (sshdDir string) {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(main, []byte(stockSSHDConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	prevDry, prevRel, prevSock, prevPkg := system.DryRun, hostOSRelease, sshSocketActivated, pkgInstalled
	prevMain, prevDropIn, prevSockDropIn, prevGen := sshdConfigPath, sshdDropInPath, sshSocketDropIn, sshSocketGenerators
	system.DryRun = true
	system.CommandLog = nil
	hostOSRelease = func() system.OSRelease { return rel }
	sshSocketActivated = func() bool { return socket }
	pkgInstalled = func(string) bool { return false } // a pristine host
	sshdConfigPath = main
	sshdDropInPath = filepath.Join(dir, "sshd_config.d", "00-forge.conf")
	sshSocketDropIn = filepath.Join(dir, "ssh.socket.d", "00-forge.conf")
	sshSocketGenerators = []string{filepath.Join(dir, "no-such-generator")}
	t.Cleanup(func() {
		system.DryRun, hostOSRelease, sshSocketActivated, pkgInstalled = prevDry, prevRel, prevSock, prevPkg
		sshdConfigPath, sshdDropInPath, sshSocketDropIn, sshSocketGenerators = prevMain, prevDropIn, prevSockDropIn, prevGen
		system.CommandLog = nil
	})
	return dir
}

func runAll(t *testing.T, cfg config.Config) (*Context, string) {
	t.Helper()
	st, ctx := BuildSteps(cfg)
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			continue
		}
		if err := s.Run(ctx); err != nil {
			t.Fatalf("step %q failed: %v", s.Name, err)
		}
	}
	return ctx, strings.Join(system.CommandLog, "\n")
}

func testConfig() config.Config {
	cfg := config.Default()
	cfg.SSHPort = 2222
	cfg.AdminKeyValue = "ssh-ed25519 AAAAC3NzaC1lZDI1 admin@laptop"
	cfg.TailscaleAuthKey = "tskey-auth-TESTONLY"
	return cfg
}

// TestDistroRepoMapping provisions (dry-run) as each supported distro and
// derivative, checking that Docker and Tailscale repos use the upstream
// Ubuntu/Debian codename — derivatives' own codenames don't exist upstream.
func TestDistroRepoMapping(t *testing.T) {
	cases := []struct {
		name   string
		rel    system.OSRelease
		family string
		code   string
	}{
		{"ubuntu-22.04", ubuntuJammy, "ubuntu", "jammy"},
		{"ubuntu-24.04", ubuntuNoble, "ubuntu", "noble"},
		{"debian-12", debian12, "debian", "bookworm"},
		{"debian-13", debian13, "debian", "trixie"},
		{"mint-22", mint22, "ubuntu", "noble"},
		{"lmde-6", lmde6, "debian", "bookworm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dryRunAs(t, tc.rel, false)
			ctx, log := runAll(t, testConfig())
			for _, want := range []string{
				"https://download.docker.com/linux/" + tc.family + "/dists/" + tc.code + "/Release",
				"https://download.docker.com/linux/" + tc.family + "/gpg",
				"https://pkgs.tailscale.com/stable/" + tc.family + "/" + tc.code + ".noarmor.gpg",
			} {
				if !strings.Contains(log, want) {
					t.Errorf("expected %q in command log", want)
				}
			}
			if ctx.Platform.Family != tc.family || ctx.Platform.Codename != tc.code {
				t.Errorf("platform = %s/%s", ctx.Platform.Family, ctx.Platform.Codename)
			}
			if tc.rel.ID == "linuxmint" && strings.Contains(log, tc.rel.Codename) {
				t.Errorf("derivative codename %q must not reach upstream URLs", tc.rel.Codename)
			}
		})
	}
}

func TestPreflightRejectsNonDebian(t *testing.T) {
	dryRunAs(t, system.OSRelease{ID: "fedora", Pretty: "Fedora Linux 42"}, false)
	_, ctx := BuildSteps(testConfig())
	if err := preflightStep().Run(ctx); err == nil || !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("expected unsupported OS error, got %v", err)
	}
}

// TestSSHDropInWinsOverCloudInit checks forge writes sshd_config.d/00-forge.conf
// (which sorts before cloud-init's 50-cloud-init.conf) when the stock Include is
// present, instead of editing values in the main file that would lose.
func TestSSHDropInWinsOverCloudInit(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	_, log := runAll(t, testConfig())
	if !strings.Contains(log, "write "+sshdDropInPath) {
		t.Fatalf("expected the drop-in %s to be written:\n%s", sshdDropInPath, log)
	}
	if strings.Contains(log, "write "+sshdConfigPath+" (") {
		t.Error("main sshd_config has no active Port line and must not be rewritten")
	}
	got := renderSSHDDropIn(sshdOptions(testConfig()))
	for _, want := range []string{"Port 2222\n", "PasswordAuthentication no\n", "PermitRootLogin no\n", "AllowUsers deploy\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("drop-in missing %q:\n%s", want, got)
		}
	}
}

func TestSocketActivatedSSHRestart(t *testing.T) {
	dryRunAs(t, ubuntuNoble, true)
	_, log := runAll(t, testConfig())
	for _, want := range []string{
		"write " + sshSocketDropIn, // no generator in the fixture → explicit ListenStream
		"systemctl daemon-reload",
		"systemctl restart ssh.socket",
		"systemctl restart ssh.service",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("expected %q in command log", want)
		}
	}
}

func TestSocketDropInListensOnBothFamilies(t *testing.T) {
	// Ubuntu's ssh.socket sets BindIPv6Only=ipv6-only, so the drop-in must name
	// an IPv4 address explicitly or IPv4 clients are locked out.
	got := sshSocketDropInFor(2222)
	for _, want := range []string{"ListenStream=\n", "ListenStream=0.0.0.0:2222\n", "ListenStream=[::]:2222\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("socket drop-in missing %q:\n%s", want, got)
		}
	}
}

func TestSSHBanner(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback networking")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	if err := sshBanner(ln.Addr().String()); err != nil {
		t.Fatalf("banner not recognised: %v", err)
	}

	http, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer http.Close()
	go func() {
		c, err := http.Accept()
		if err == nil {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
			c.Close()
		}
	}()
	if err := sshBanner(http.Addr().String()); err == nil {
		t.Fatal("a non-SSH service must not pass as sshd")
	}
}

func TestSocketActivatedUsesGenerator(t *testing.T) {
	dir := dryRunAs(t, ubuntuNoble, true)
	gen := filepath.Join(dir, "sshd-socket-generator")
	if err := os.WriteFile(gen, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	sshSocketGenerators = []string{gen}
	_, log := runAll(t, testConfig())
	if strings.Contains(log, "write "+sshSocketDropIn) {
		t.Error("with Ubuntu's sshd-socket-generator present, no explicit socket drop-in is needed")
	}
	if !strings.Contains(log, "systemctl restart ssh.socket") {
		t.Error("socket must be restarted to rebind the port")
	}
}

func TestNoTransitionalRuleWhenPortUnchanged(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	cfg := testConfig()
	cfg.SSHPort = 22
	_, log := runAll(t, cfg)
	if strings.Contains(log, "ufw delete allow") {
		t.Errorf("port unchanged — nothing to close:\n%s", log)
	}
}

func TestSSHDMismatches(t *testing.T) {
	cfg := testConfig()
	good := "port 2222\nlistenaddress [::]:2222\nlistenaddress 0.0.0.0:2222\nallowusers deploy\n" +
		"permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"
	if bad := sshdMismatches(parseSSHDT(good), cfg); len(bad) != 0 {
		t.Fatalf("unexpected mismatches: %v", bad)
	}

	// What a cloud image looks like when values land in the main file only:
	// 50-cloud-init.conf wins, and the old Port 22 line keeps listening.
	overridden := "port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress 0.0.0.0:2222\nallowusers deploy\n" +
		"permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\n"
	bad := sshdMismatches(parseSSHDT(overridden), cfg)
	joined := strings.Join(bad, "\n")
	for _, want := range []string{"port:", "listenaddress 0.0.0.0:22", "passwordauthentication"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a %q mismatch, got:\n%s", want, joined)
		}
	}
}

func TestSSHDOptionsKeepsRootWhenAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.DisableRootLogin = false
	for _, o := range sshdOptions(cfg) {
		if o.key == "AllowUsers" && o.value != "deploy root" {
			t.Errorf("AllowUsers = %q; root login was kept, so root must be allowed", o.value)
		}
		if o.key == "PermitRootLogin" {
			t.Error("PermitRootLogin must not be forced when root login is kept")
		}
	}
}

func TestCommentOutPort(t *testing.T) {
	in := "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n#Port 2200\n  Port 443\nPermitRootLogin yes\n"
	out := commentOutDirective(in, "Port")
	if strings.Contains(out, "\nPort 22") || strings.Contains(out, "\n  Port 443") {
		t.Errorf("active Port lines left:\n%s", out)
	}
	if !strings.Contains(out, "#Port 2200\n") || !strings.Contains(out, "PermitRootLogin yes") {
		t.Errorf("unrelated lines changed:\n%s", out)
	}
}

func TestSetSSHDOptionLegacyPrepends(t *testing.T) {
	in := "PermitRootLogin yes\nMatch User sftp\n    ForceCommand internal-sftp\n"
	out := setSSHDOption(in, "PasswordAuthentication", "no")
	if !strings.HasPrefix(out, "PasswordAuthentication no\n") {
		t.Errorf("new directive must go before any Match block:\n%s", out)
	}
	out = setSSHDOption(out, "PermitRootLogin", "no")
	if strings.Count(out, "PermitRootLogin") != 1 || !strings.Contains(out, "PermitRootLogin no") {
		t.Errorf("existing directive must be replaced in place:\n%s", out)
	}
}

func TestHostsWithName(t *testing.T) {
	debian := "127.0.0.1\tlocalhost\n127.0.1.1\told-name\n\n::1 localhost ip6-localhost\n"
	if got := hostsWithName(debian, "web-01"); !strings.Contains(got, "127.0.1.1\tweb-01\n") || strings.Contains(got, "old-name") {
		t.Errorf("existing 127.0.1.1 entry not replaced:\n%s", got)
	}
	minimal := "127.0.0.1 localhost\n::1 localhost\n"
	got := hostsWithName(minimal, "web-01.example.com")
	if !strings.Contains(got, "127.0.0.1 localhost\n127.0.1.1\tweb-01.example.com web-01\n") {
		t.Errorf("entry not inserted after localhost:\n%s", got)
	}
	if again := hostsWithName(got, "web-01.example.com"); again != got {
		t.Errorf("not idempotent:\n%s", again)
	}
}

func TestMergeDaemonJSON(t *testing.T) {
	out, err := mergeDaemonJSON([]byte(`{"registry-mirrors":["https://mirror.example"],"log-driver":"journald"}`))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("merged output is not JSON: %v\n%s", err, out)
	}
	if got["registry-mirrors"] == nil {
		t.Error("existing settings must be kept")
	}
	if got["log-driver"] != "journald" || got["log-opts"] != nil {
		t.Error("an operator-chosen log driver must not be replaced")
	}
	if got["no-new-privileges"] != true || got["live-restore"] != true {
		t.Error("hardening keys missing")
	}

	fresh, err := mergeDaemonJSON(nil)
	if err != nil || !strings.Contains(string(fresh), `"max-size": "10m"`) {
		t.Errorf("fresh daemon.json should get log rotation: %v\n%s", err, fresh)
	}
	if _, err := mergeDaemonJSON([]byte("{not json")); err == nil {
		t.Error("invalid JSON must be refused, not clobbered")
	}
}

func TestTelegramValidation(t *testing.T) {
	if err := config.ValidTelegramToken("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"); err != nil {
		t.Errorf("real-shaped token rejected: %v", err)
	}
	for _, bad := range []string{"", "token", "123:short", "123456789:AAH$(reboot)aaaaaaaaaaaaaaaaaaaaaaaaa", "123456789:AAHdq\nTcvCH1vGWJxfSeofSAs0K5PALDsaw"} {
		if config.ValidTelegramToken(bad) == nil {
			t.Errorf("token %q must be rejected", bad)
		}
	}
	for _, ok := range []string{"123456789", "-1001234567890", "@my_channel"} {
		if err := config.ValidTelegramChatID(ok); err != nil {
			t.Errorf("chat id %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "abc", "12 34", "@x", "1;reboot"} {
		if config.ValidTelegramChatID(bad) == nil {
			t.Errorf("chat id %q must be rejected", bad)
		}
	}
}

func TestLegacySSHRCRemoval(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	if !strings.Contains(legacySSHRCBlock, "notify.sh") {
		t.Fatal("legacy block must match what old versions wrote")
	}
	// The pam hook must be optional so it can never block a login.
	if !strings.HasPrefix(pamLoginHookLine, "session optional pam_exec.so") {
		t.Errorf("unsafe PAM line: %q", pamLoginHookLine)
	}
	if strings.Contains(notifyScript, `"https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`) {
		t.Error("bot token must not be passed to curl on the command line")
	}
}

func TestTailscaleBrowserLogin(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	cfg := testConfig()
	cfg.TailscaleAuthKey = "" // no key: log in with a link/QR
	ctx, log := runAll(t, cfg)
	if !strings.Contains(log, "tailscale up --ssh") || strings.Contains(log, "--auth-key") {
		t.Errorf("expected an interactive `tailscale up --ssh` without a key:\n%s", log)
	}
	if !strings.Contains(strings.Join(ctx.Notes, "\n"), "Disable key expiry") {
		t.Error("browser-approved machines expire — the summary must say how to disable key expiry")
	}

	// The link tailscale prints becomes an operator action with the URL.
	t.Cleanup(func() { system.SetAttention(nil) })
	watchTailscaleLogin("To authenticate, visit:")
	if system.CurrentAttention() != nil {
		t.Fatal("no URL yet — nothing to show")
	}
	watchTailscaleLogin("\thttps://login.tailscale.com/a/1a2b3c4d5e6f")
	a := system.CurrentAttention()
	if a == nil || a.URL != "https://login.tailscale.com/a/1a2b3c4d5e6f" {
		t.Fatalf("login URL not captured: %+v", a)
	}
}
