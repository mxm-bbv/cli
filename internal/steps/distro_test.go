package steps

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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

	// Tailnet-only agent: setup logs in on the spot and the agent is up on
	// the tailnet address when it ends.
	ctx, log := runAll(t, cfg)
	if !strings.Contains(log, "tailscale up --ssh") || strings.Contains(log, "--auth-key") {
		t.Errorf("expected an interactive `tailscale up --ssh` during setup:\n%s", log)
	}
	if !strings.Contains(log, "-p <tailnet-ip>:9001:9001") || ctx.AgentDeferred {
		t.Errorf("the agent must start on the tailnet IP during setup:\n%s", log)
	}
	if !strings.Contains(strings.Join(ctx.Notes, "\n"), "Disable key expiry") {
		t.Error("browser-approved machines expire — the summary must say how to disable key expiry")
	}

	// No agent: Tailscale is only installed, login is left for later.
	system.CommandLog = nil
	cfg.InstallPortainer = false
	ctx, log = runAll(t, cfg)
	if strings.Contains(log, "tailscale up") || !strings.Contains(strings.Join(ctx.Notes, "\n"), "sudo forge tailscale") {
		t.Errorf("without a tailnet agent the login waits for `forge tailscale`:\n%s", log)
	}

	// `forge tailscale` later: interactive login.
	system.CommandLog = nil
	st, ctx := TailscaleSteps(cfg)
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			continue
		}
		if err := s.Run(ctx); err != nil {
			t.Fatalf("step %q failed: %v", s.Name, err)
		}
	}
	if log = strings.Join(system.CommandLog, "\n"); !strings.Contains(log, "tailscale up --ssh") {
		t.Errorf("forge tailscale must log in:\n%s", log)
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

// TestGitHubDeviceCode: the code line gh prints (captured from gh 2.103 run
// without a terminal) becomes an operator action with the code and the URL.
func TestGitHubDeviceCode(t *testing.T) {
	t.Cleanup(func() { system.SetAttention(nil) })
	watchGitHubLogin("! Failed to copy one-time code to clipboard")
	if system.CurrentAttention() != nil {
		t.Fatal("no code yet — nothing to show")
	}
	watchGitHubLogin("! First copy your one-time code: 6830-73D2")
	a := system.CurrentAttention()
	if a == nil || a.Code != "6830-73D2" || a.URL != "https://github.com/login/device" {
		t.Fatalf("device code not captured: %+v", a)
	}
}

func TestDeployKeyNames(t *testing.T) {
	a, b := deployKeyFor("/h/.ssh", "a/b-c"), deployKeyFor("/h/.ssh", "a-b/c")
	if a.alias == b.alias || a.path == b.path {
		t.Errorf("different repos must get different keys: %+v %+v", a, b)
	}
	if k := deployKeyFor("/h/.ssh", "Mxm-Bbv/App"); k.alias != "github-mxm-bbv--app" || k.path != "/h/.ssh/github-mxm-bbv--app" {
		t.Errorf("unexpected naming: %+v", k)
	}
}

// TestSSHDCryptoPolicy: weak algorithms are removed from OpenSSH's defaults
// with "-" lists (valid on 8.9–10.x, verified with sshd -t on every supported
// release) rather than replaced by a fixed list that would drop ML-KEM.
func TestSSHDCryptoPolicy(t *testing.T) {
	conf := renderSSHDDropIn(sshdOptions(testConfig()))
	for _, want := range []string{
		"KexAlgorithms -ecdh-sha2-nistp256,",
		"MACs -umac-64-etm@openssh.com,",
		"LogLevel VERBOSE",
		"X11Forwarding no",
		"AllowAgentForwarding no",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("drop-in lacks %q:\n%s", want, conf)
		}
	}
	for _, risky := range []string{"MaxAuthTries", "AllowTcpForwarding", "Ciphers ", "HostKeyAlgorithms"} {
		if strings.Contains(conf, risky) {
			t.Errorf("%s locks out agents with several keys / VS Code / pinned host keys — leave the default", risky)
		}
	}
}

func TestTailnetAddresses(t *testing.T) {
	for ip, want := range map[string]bool{
		"100.101.102.103": true, "100.64.0.1": true, "[fd7a:115c:a1e0::1]": true,
		"100.128.0.1": false, "203.0.113.7": false, "10.0.0.5": false, "": false,
	} {
		if got := IsTailnetIP(ip); got != want {
			t.Errorf("IsTailnetIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

// TestFirewallKeepsSSHTailnetOnly: once SSH was closed to the internet, a
// re-run of the setup must not reopen it.
func TestFirewallKeepsSSHTailnetOnly(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	cfg := testConfig()
	cfg.SSHTailnetOnly = true
	_, log := runAll(t, cfg)
	for _, rule := range []string{"ufw allow 22/tcp", "ufw allow 2222/tcp"} {
		if strings.Contains(log, rule) {
			t.Errorf("tailnet-only SSH reopened by %q", rule)
		}
	}
	if !strings.Contains(log, "ufw allow in on tailscale0") {
		t.Error("the tailnet must stay trusted, or nobody gets in")
	}
}

// TestSessionClient: sudo strips SSH_CONNECTION, so the client address is
// read from the nearest ancestor that still has it.
func TestSessionClient(t *testing.T) {
	if os.Getenv("FORGE_SESSION_HELPER") == "1" {
		fmt.Print(SessionClient())
		os.Exit(0)
	}
	cmd := exec.Command("sh", "-c", `env -u SSH_CONNECTION FORGE_SESSION_HELPER=1 "$0" -test.run '^TestSessionClient$'`, os.Args[0])
	cmd.Env = append(os.Environ(), "SSH_CONNECTION=100.64.1.2 51234 203.0.113.7 22")
	out, err := cmd.Output()
	if err != nil || string(out) != "100.64.1.2" {
		t.Fatalf("got %q (%v), want the shell's SSH client 100.64.1.2", out, err)
	}
}

func TestSSHOpenInUFW(t *testing.T) {
	const head = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
	for _, tc := range []struct {
		status string
		open   bool
	}{
		{"", true}, // ufw not installed / no output
		{"Status: inactive\n", true},
		{head + "2222/tcp                   ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n", true},
		{head + "OpenSSH                    ALLOW       Anywhere\n", true},
		{head + "80/tcp                     ALLOW       Anywhere\nAnywhere on tailscale0     ALLOW       Anywhere\n", false},
		{head + "22/tcp                     ALLOW       Anywhere\n", false}, // not sshd's port
	} {
		if got := sshOpenInUFW(tc.status, []int{2222}); got != tc.open {
			t.Errorf("sshOpenInUFW(%q) = %v, want %v", tc.status, got, tc.open)
		}
	}
}

// TestDeployKeyCheckReadsStderr: GitHub's "successfully authenticated" comes
// on stderr with exit status 1 — reading stdout only made every working key
// look refused (v0.4.2).
func TestDeployKeyCheckReadsStderr(t *testing.T) {
	bin := t.TempDir()
	fake := func(script string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, "runuser"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	prev := system.DryRun
	system.DryRun = false
	t.Cleanup(func() { system.DryRun = prev })
	k := deployKeyFor("/home/deploy/.ssh", "MR-Studio-KZ-UA/caddy-core")

	fake(`echo "Hi MR-Studio-KZ-UA/caddy-core! You've successfully authenticated, but GitHub does not provide shell access." >&2; exit 1`)
	if ok, out := deployKeyCheck("deploy", k); !ok {
		t.Errorf("GitHub's greeting on stderr must count as success, got %q", out)
	}
	fake(`echo "git@github.com: Permission denied (publickey)." >&2; exit 255`)
	if ok, out := deployKeyCheck("deploy", k); ok || !strings.Contains(out, "Permission denied") {
		t.Errorf("a refused key must fail and say why, got %v %q", ok, out)
	}
}

// TestCaddyFallsBackWithoutGitHub: when the clone fails, the built-in copy of
// the caddy-core layout is written instead of failing the setup.
func TestCaddyFallsBackWithoutGitHub(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	if err := writeBuiltinCaddy("deploy", "/home/deploy/caddy-core"); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(system.CommandLog, "\n")
	for _, want := range []string{
		"write /home/deploy/caddy-core/docker-compose.prod.yml",
		"write /home/deploy/caddy-core/core/prod/caddy/Caddyfile",
		"write /home/deploy/caddy-core/.forge-builtin",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q:\n%s", want, log)
		}
	}
	compose := builtinCaddyFiles["docker-compose.prod.yml"]
	for _, want := range []string{"container_name: main-server", "proxy-network", "\"80:80\"", "\"443:443\"", "${PROJECTS_PATH}:/projects:ro"} {
		if !strings.Contains(compose, want) {
			t.Errorf("built-in compose must match caddy-core's layout: lacks %q", want)
		}
	}
}

// TestSharedAgentSecret: a Portainer Server has ONE AGENT_SECRET for all its
// agents, so a given secret is used as-is (and kept for later runs); only
// the first server generates one.
func TestSharedAgentSecret(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	prev := agentEnvPath
	agentEnvPath = filepath.Join(t.TempDir(), "agent.env")
	t.Cleanup(func() { agentEnvPath = prev })

	cfg := testConfig()
	cfg.AgentSecret = "shared-secret-of-my-portainer"
	ctx, log := runAll(t, cfg)
	if ctx.AgentSecret != cfg.AgentSecret || ctx.AgentSecretNew {
		t.Errorf("the given secret must be used, got %q (new=%v)", ctx.AgentSecret, ctx.AgentSecretNew)
	}
	if strings.Contains(log, cfg.AgentSecret) || !strings.Contains(log, "write "+agentEnvPath+" (600)") {
		t.Errorf("the secret is kept root-only and never logged:\n%s", log)
	}

	system.CommandLog = nil
	cfg.AgentSecret = ""
	if ctx, _ = runAll(t, cfg); !ctx.AgentSecretNew || len(ctx.AgentSecret) != 32 {
		t.Errorf("without one, the first server generates it: %q new=%v", ctx.AgentSecret, ctx.AgentSecretNew)
	}
}
