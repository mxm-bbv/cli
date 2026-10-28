package steps

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// Paths are variables so tests can point them at fixtures.
var (
	sshdConfigPath  = "/etc/ssh/sshd_config"
	sshdDropInPath  = "/etc/ssh/sshd_config.d/00-forge.conf"
	sshSocketDropIn = "/etc/systemd/system/ssh.socket.d/00-forge.conf"
)

// sshSocketGenerators read Port/ListenAddress from sshd_config and configure
// ssh.socket accordingly (Ubuntu 24.04+). Without one, forge writes an explicit
// ssh.socket drop-in.
var sshSocketGenerators = []string{
	"/usr/lib/systemd/system-generators/sshd-socket-generator",
	"/lib/systemd/system-generators/sshd-socket-generator",
}

// sshdIncludeRe matches the stock "Include /etc/ssh/sshd_config.d/*.conf" line
// (Ubuntu 20.04+, Debian 11+).
var sshdIncludeRe = regexp.MustCompile(`(?mi)^[ \t]*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf[ \t]*$`)

func sshHardeningStep() Step {
	return Step{
		Name: "SSH hardening: disable root / passwords, restart sshd",
		Skip: func(c *Context) bool {
			return !c.Cfg.DisableRootLogin && !c.Cfg.DisablePassauth && sshPort(c.Cfg.SSHPort) == 22
		},
		Run: func(c *Context) error {
			cfg := c.Cfg
			port := sshPort(cfg.SSHPort)

			// Lockout guard: never disable password auth unless the deploy user
			// actually has a working key, so we can't cut off access.
			if cfg.DisablePassauth && !system.DryRun {
				ak := cfg.HomeDir() + "/.ssh/authorized_keys"
				if !c.AdminKeyInstalled && !hasAuthorizedKey(ak) {
					return fmt.Errorf(
						"refusing to disable password auth: %s has no SSH key in %s — you would be locked out.\n"+
							"      Re-run and choose Fetch/Paste for your admin key, or answer 'No' to disabling password auth.",
						cfg.Username, ak)
				}
			}
			if !system.DryRun && !system.CommandExists("sshd") {
				return errors.New("sshd not found — install openssh-server first")
			}

			oldPorts := currentSSHPorts()
			if !slices.Contains(oldPorts, port) {
				if who := listenerOn(port); who != "" {
					return fmt.Errorf("port %d is already in use, sshd could not bind it:\n      %s", port, who)
				}
			}

			revert, err := applySSHDConfig(cfg)
			if err != nil {
				return err
			}
			if err := verifyEffectiveSSHD(cfg); err != nil {
				revert()
				return err
			}

			socket := sshSocketActivated()
			wroteSocketDropIn, err := restartSSHD(port, socket)
			if err == nil {
				err = waitListening(port)
			}
			if err != nil {
				// Never leave the box with a broken or unreachable sshd: put the
				// previous config back and restart onto it.
				revert()
				if wroteSocketDropIn {
					_ = system.RemoveFile(sshSocketDropIn)
				}
				_, _ = restartSSHD(0, socket)
				return fmt.Errorf("%w\n      Previous sshd config restored and sshd restarted on it; your session is unaffected", err)
			}

			// sshd is verified on the new port — now close the old one(s) the
			// firewall step kept open for the transition.
			if cfg.EnableFirewall {
				for _, p := range oldPorts {
					if p != port {
						_, _ = system.Run("ufw", "delete", "allow", fmt.Sprintf("%d/tcp", p))
						c.Notes = append(c.Notes, fmt.Sprintf("old SSH port %d closed in UFW", p))
					}
				}
			}
			if socket {
				c.Notes = append(c.Notes, "sshd is socket-activated (ssh.socket) — its listening port was updated too")
			}
			c.Notes = append(c.Notes, fmt.Sprintf("sshd restarted on port %d — keep this session open and verify key login in a NEW terminal", port))
			return nil
		},
	}
}

type sshdOption struct{ key, value string }

// sshdOptions is forge's sshd policy, in a stable order.
func sshdOptions(cfg config.Config) []sshdOption {
	allow := cfg.Username
	if !cfg.DisableRootLogin && cfg.Username != "root" {
		// AllowUsers is a whitelist: leaving root out would block it even
		// though the operator chose to keep root login.
		allow += " root"
	}
	opts := []sshdOption{
		{"Port", strconv.Itoa(sshPort(cfg.SSHPort))},
		{"AllowUsers", allow},
		{"PubkeyAuthentication", "yes"},
		{"KbdInteractiveAuthentication", "no"},
		{"UsePAM", "yes"},
	}
	if cfg.DisableRootLogin {
		opts = append(opts, sshdOption{"PermitRootLogin", "no"})
	}
	if cfg.DisablePassauth {
		opts = append(opts, sshdOption{"PasswordAuthentication", "no"})
	}
	return opts
}

// applySSHDConfig writes forge's policy and validates it with `sshd -t`. It
// returns a revert func that restores the previous files.
//
// sshd uses the FIRST value it reads for most directives, and the stock config
// starts with "Include /etc/ssh/sshd_config.d/*.conf". Editing the main file is
// therefore not enough: cloud images ship 50-cloud-init.conf with
// "PasswordAuthentication yes", which would silently win. forge writes
// 00-forge.conf, which sorts first and so takes precedence.
func applySSHDConfig(cfg config.Config) (revert func(), err error) {
	main, err := readFileOrEmpty(sshdConfigPath)
	if err != nil {
		return nil, err
	}
	if err := system.BackupFile(sshdConfigPath); err != nil {
		return nil, err
	}
	opts := sshdOptions(cfg)

	if sshdIncludeRe.MatchString(main) {
		prevDropIn, err := readFileOrEmpty(sshdDropInPath)
		if err != nil {
			return nil, err
		}
		// Port is the exception to first-value-wins: every Port line adds a
		// listener. An active Port in the main file would keep the old port
		// open next to the new one.
		newMain := commentOutDirective(main, "Port")
		if newMain != main {
			if err := system.WriteFile(sshdConfigPath, newMain, 0o644); err != nil {
				return nil, err
			}
		}
		if err := system.WriteFile(sshdDropInPath, renderSSHDDropIn(opts), 0o644); err != nil {
			return nil, err
		}
		revert = func() {
			_ = restoreFile(sshdDropInPath, prevDropIn)
			if newMain != main {
				_ = restoreFile(sshdConfigPath, main)
			}
		}
	} else {
		// Legacy layout without the Include: edit the main file in place.
		content := main
		for _, o := range opts {
			content = setSSHDOption(content, o.key, o.value)
		}
		if err := system.WriteFile(sshdConfigPath, content, 0o644); err != nil {
			return nil, err
		}
		revert = func() { _ = restoreFile(sshdConfigPath, main) }
	}

	// Validate before restarting — never lock ourselves out on a typo.
	ensureSSHDRuntimeDir()
	if _, err := system.Run("sshd", "-t"); err != nil {
		revert()
		return nil, fmt.Errorf("sshd config validation failed, NOT restarting (changes reverted): %w", err)
	}
	return revert, nil
}

func renderSSHDDropIn(opts []sshdOption) string {
	var b strings.Builder
	b.WriteString("# Managed by forge — rerun forge to change. Sorts first in sshd_config.d,\n")
	b.WriteString("# so these values win over later drop-ins (e.g. 50-cloud-init.conf).\n")
	for _, o := range opts {
		b.WriteString(o.key + " " + o.value + "\n")
	}
	return b.String()
}

// verifyEffectiveSSHD asks sshd what it will actually enforce (`sshd -T`) and
// fails if any forge setting was overridden somewhere else.
func verifyEffectiveSSHD(cfg config.Config) error {
	system.CommandLog = append(system.CommandLog, "sshd -T (verify effective settings)")
	if system.DryRun {
		return nil
	}
	out, err := system.Output("sshd", "-T")
	if err != nil {
		return fmt.Errorf("sshd -T: %w", err)
	}
	if bad := sshdMismatches(parseSSHDT(out), cfg); len(bad) > 0 {
		return fmt.Errorf("another sshd config file overrides forge (changes reverted):\n      %s\n"+
			"      Inspect with `sshd -T` and the files in /etc/ssh/sshd_config.d/", strings.Join(bad, "\n      "))
	}
	return nil
}

// parseSSHDT parses `sshd -T` output (lowercase "key value" lines) into
// key → values; repeated keys (port, listenaddress, allowusers) accumulate.
func parseSSHDT(out string) map[string][]string {
	eff := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		eff[k] = append(eff[k], strings.Fields(v)...)
	}
	return eff
}

// sshdMismatches lists every effective setting that differs from cfg.
func sshdMismatches(eff map[string][]string, cfg config.Config) []string {
	var bad []string
	port := strconv.Itoa(sshPort(cfg.SSHPort))
	if !slices.Equal(eff["port"], []string{port}) {
		bad = append(bad, fmt.Sprintf("port: want %s, sshd uses %v", port, eff["port"]))
	}
	for _, la := range eff["listenaddress"] {
		if !strings.HasSuffix(la, ":"+port) {
			bad = append(bad, "listenaddress "+la+" is not on port "+port)
		}
	}
	if !slices.Contains(eff["allowusers"], cfg.Username) {
		bad = append(bad, fmt.Sprintf("allowusers: %s missing (sshd uses %v)", cfg.Username, eff["allowusers"]))
	}
	check := func(key, want string) {
		if got := eff[key]; len(got) != 1 || got[0] != want {
			bad = append(bad, fmt.Sprintf("%s: want %s, sshd uses %v", key, want, got))
		}
	}
	if cfg.DisableRootLogin {
		check("permitrootlogin", "no")
	}
	if cfg.DisablePassauth {
		check("passwordauthentication", "no")
		check("kbdinteractiveauthentication", "no")
	}
	return bad
}

// commentOutDirective comments out every active line for key.
func commentOutDirective(content, key string) string {
	re := regexp.MustCompile(`(?mi)^([ \t]*)(` + regexp.QuoteMeta(key) + `[ \t]+.*)$`)
	return re.ReplaceAllString(content, "${1}#${2}  # forge: set in sshd_config.d/00-forge.conf")
}

// setSSHDOption replaces an existing (possibly commented) directive or adds a
// new one, ensuring exactly one active line for the key. New lines go at the
// top: sshd takes the first value, and anything appended at the end could land
// inside a trailing Match block.
func setSSHDOption(content, key, value string) string {
	line := key + " " + value
	re := regexp.MustCompile(`(?m)^[#\s]*` + regexp.QuoteMeta(key) + `\s+.*$`)
	if re.MatchString(content) {
		return re.ReplaceAllLiteralString(content, line)
	}
	return line + "\n" + content
}

// sshSocketActivated reports whether sshd runs socket-activated via
// ssh.socket (Ubuntu 22.10+ default). The listening port then belongs to the
// socket unit, not to sshd_config alone. A variable so tests can pin it.
var sshSocketActivated = func() bool {
	for _, args := range [][]string{{"is-enabled", "ssh.socket"}, {"is-active", "ssh.socket"}} {
		if out, err := system.Output("systemctl", args...); err == nil && (out == "enabled" || out == "active") {
			return true
		}
	}
	return false
}

// restartSSHD restarts sshd so the new config (and port) take effect. port 0
// means "port unchanged" (used when restoring). It reports whether it wrote the
// explicit ssh.socket drop-in, so a rollback can remove it.
func restartSSHD(port int, socket bool) (wroteSocketDropIn bool, err error) {
	if !socket {
		_, err = system.Run("systemctl", "restart", sshServiceName())
		return false, err
	}
	if port != 0 && !anyFileExists(sshSocketGenerators) {
		// No generator (Ubuntu 22.10–23.10): pin the socket's port ourselves.
		if _, err := system.Run("install", "-m", "0755", "-d", strings.TrimSuffix(sshSocketDropIn, "/00-forge.conf")); err != nil {
			return false, err
		}
		if err := system.WriteFile(sshSocketDropIn, sshSocketDropInFor(port), 0o644); err != nil {
			return false, err
		}
		wroteSocketDropIn = true
	}
	// daemon-reload re-runs the generator (or loads the drop-in); restarting
	// the socket rebinds the port. ssh.service has KillMode=process, so open
	// sessions survive both restarts.
	for _, args := range [][]string{
		{"daemon-reload"},
		{"restart", "ssh.socket"},
		{"restart", "ssh.service"},
	} {
		if _, err := system.Run("systemctl", args...); err != nil {
			return wroteSocketDropIn, err
		}
	}
	return wroteSocketDropIn, nil
}

// sshSocketDropInFor renders ssh.socket listen addresses in the same shape
// Ubuntu's sshd-socket-generator emits. The empty ListenStream= clears the
// packaged :22 entries; both families are listed because the packaged unit
// sets BindIPv6Only=ipv6-only — a bare "ListenStream=PORT" would then be
// IPv6-only and lock out every IPv4 client.
func sshSocketDropInFor(port int) string {
	return fmt.Sprintf("# Managed by forge.\n[Socket]\nListenStream=\nListenStream=0.0.0.0:%d\nListenStream=[::]:%d\n", port, port)
}

// waitListening confirms sshd answers on the new port after a restart: a real
// TCP connection that must return an "SSH-" banner, retried briefly while
// sshd/systemd bind. A listening socket alone isn't proof — an IPv6-only bind
// would still show up in `ss` while every IPv4 client is locked out.
func waitListening(port int) error {
	system.CommandLog = append(system.CommandLog, fmt.Sprintf("connect 127.0.0.1:%d, expect SSH banner (verify sshd)", port))
	if system.DryRun {
		return nil
	}
	targets := sshProbeAddrs(port)
	var lastErr error
	for i := 0; i < 20; i++ {
		for _, addr := range targets {
			if lastErr = sshBanner(addr); lastErr == nil {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("sshd restarted but does not answer on port %d (%v)", port, lastErr)
}

// sshProbeAddrs returns where to probe sshd: loopback covers wildcard and
// dual-stack binds; specific ListenAddress values are probed directly.
func sshProbeAddrs(port int) []string {
	addrs := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	if out, err := system.Output("sshd", "-T"); err == nil {
		for _, la := range parseSSHDT(out)["listenaddress"] {
			host, p, err := net.SplitHostPort(la)
			if err != nil || p != strconv.Itoa(port) || host == "0.0.0.0" || host == "::" {
				continue
			}
			addrs = append(addrs, la)
		}
	}
	return addrs
}

// sshBanner connects to addr and checks the server speaks SSH.
func sshBanner(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n >= 4 && string(buf[:4]) == "SSH-" {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("unexpected banner %q", buf[:n])
	}
	return fmt.Errorf("%s: %w", addr, err)
}

// listenerOn returns the `ss` line(s) for a TCP listener on port, or "".
func listenerOn(port int) string {
	if system.DryRun {
		return ""
	}
	out, err := system.Output("ss", "-Htlnp", "sport", "=", fmt.Sprintf(":%d", port))
	if err != nil {
		return ""
	}
	return out
}

// currentSSHPorts returns the ports sshd is configured to listen on right now
// (from `sshd -T`), falling back to 22.
func currentSSHPorts() []int {
	if system.DryRun {
		return []int{22}
	}
	ensureSSHDRuntimeDir()
	out, err := system.Output("sshd", "-T")
	if err != nil {
		return []int{22}
	}
	var ports []int
	for _, v := range parseSSHDT(out)["port"] {
		if p, err := strconv.Atoi(v); err == nil && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

// ensureSSHDRuntimeDir creates sshd's privilege-separation dir. ssh.service
// creates it on start; with socket activation (or from a provider's web
// console) the service may never have run, and `sshd -t`/`-T` then fail with
// "Missing privilege separation directory: /run/sshd".
func ensureSSHDRuntimeDir() {
	if !system.DryRun && !system.FileExists("/run/sshd") {
		_ = os.MkdirAll("/run/sshd", 0o755)
	}
}

func anyFileExists(paths []string) bool {
	for _, p := range paths {
		if system.FileExists(p) {
			return true
		}
	}
	return false
}

func readFileOrEmpty(path string) (string, error) {
	if system.DryRun && !system.FileExists(path) {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// sshServiceName returns the systemd unit for the SSH daemon (ssh on Debian/Ubuntu).
func sshServiceName() string {
	if system.FileExists("/lib/systemd/system/sshd.service") ||
		system.FileExists("/etc/systemd/system/sshd.service") {
		return "sshd"
	}
	return "ssh"
}

func autoUpdatesStep() Step {
	return Step{
		Name: "Unattended security upgrades",
		Skip: func(c *Context) bool {
			return !c.Cfg.EnableAutoUpdates ||
				system.FileExists("/etc/apt/apt.conf.d/20auto-upgrades")
		},
		Run: func(c *Context) error {
			if err := aptInstall("unattended-upgrades", "apt-listchanges"); err != nil {
				return err
			}
			conf := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
			if err := system.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", conf, 0o644); err != nil {
				return err
			}
			_, _ = system.Run("systemctl", "enable", "--now", "unattended-upgrades")
			return nil
		},
	}
}
