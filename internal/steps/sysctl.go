package steps

import (
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

var sysctlPath = "/etc/sysctl.d/90-forge.conf"

// sysctlHardening is kernel and network hardening that a Docker + Tailscale
// host tolerates. Deliberately absent: net.ipv4.ip_forward (Docker and a
// Tailscale exit node need it), accept_ra (cloud IPv6 often relies on router
// advertisements) and strict rp_filter=1 (breaks Tailscale's asymmetric
// routing; loose mode 2 still drops spoofed sources).
const sysctlHardening = `# forge: kernel & network hardening — safe with Docker and Tailscale.
# Remove this file and run "sysctl --system" to undo.

# Hide kernel addresses and the kernel log from unprivileged users.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# No unprivileged eBPF (a recurring local-root vector); harden the BPF JIT.
# 2, not 1: same protection, but 1 can't be undone without a reboot.
kernel.unprivileged_bpf_disabled = 2
net.core.bpf_jit_harden = 2
# Processes may only ptrace their own descendants.
kernel.yama.ptrace_scope = 1
# setuid programs never dump core (they could leak secrets).
fs.suid_dumpable = 0
# Only root may load TTY line disciplines (another local-root vector).
dev.tty.ldisc_autoload = 0

# SYN-flood protection; drop RSTs for TIME-WAIT sockets (RFC 1337).
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
# Ignore ICMP redirects and source-routed packets; don't send redirects.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Drop packets with spoofed source addresses (loose mode).
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# No smurf amplification, no log spam from bogus ICMP errors.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
`

// sysctlStep applies sysctlHardening. A key the kernel doesn't have is
// skipped (-e), and a value the kernel refuses becomes a note, not a failed
// setup: none of these is worth an unprovisioned server.
func sysctlStep() Step {
	return Step{
		Name: "Kernel & network hardening (sysctl)",
		Skip: func(c *Context) bool { return !c.Cfg.HardenKernel || c.Container != "" },
		Run: func(c *Context) error {
			if err := system.WriteFile(sysctlPath, sysctlHardening, 0o644); err != nil {
				return err
			}
			// Ubuntu's apport crash reporter sets fs.suid_dumpable back to 2
			// whenever it starts. It has no use on a server.
			if apportInstalled() {
				_, _ = system.Run("systemctl", "disable", "--now", "apport.service")
				if _, err := system.Run("systemctl", "mask", "apport.service"); err != nil {
					return err
				}
			}
			if out, err := system.Run("sysctl", "-q", "-e", "-p", sysctlPath); err != nil {
				c.Notes = append(c.Notes, "⚠ some kernel hardening settings were refused: "+firstLine(out))
			}
			return nil
		},
	}
}

var apportInstalled = func() bool { return pkgInstalled("apport") }

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
