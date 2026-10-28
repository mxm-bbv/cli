package steps

import (
	"fmt"
	"os"

	"github.com/mxm-bbv/cli/internal/system"
)

func preflightStep() Step {
	return Step{
		Name: "Preflight: detect OS, apt update & base tooling",
		Skip: always,
		Run: func(c *Context) error {
			p, err := system.DetectPlatform(hostOSRelease())
			if err != nil {
				return err
			}
			c.Platform = p
			if !system.DryRun && !system.HasSystemd() {
				return fmt.Errorf("%s is not running systemd — forge manages services, timers and sshd via systemctl", p.OS.Name())
			}
			if note := p.SupportNote(); note != "" {
				c.Notes = append(c.Notes, "⚠ "+note)
			}
			if ct := system.ContainerType(); ct != "" && !system.DryRun {
				c.Container = ct
				c.Notes = append(c.Notes, "⚠ running inside a "+ct+" container — swap is skipped and Docker/firewall may be limited by the host")
			}

			// Make every apt/dpkg invocation fully non-interactive so a hidden
			// needrestart/debconf prompt can never freeze the wizard.
			aptEnvReady()
			if _, err := aptGet("update", "-y"); err != nil {
				return err
			}
			// Tooling needed by later steps. sudo is not part of a minimal
			// Debian install (only Ubuntu ships it) — without it the deploy
			// user's sudo group membership is useless, and once root login is
			// disabled nobody could administer the box. iproute2 provides `ss`
			// for verifying sshd's listening port.
			if err := aptInstall("ca-certificates", "curl", "gnupg", "sudo", "openssh-client", "iproute2"); err != nil {
				return err
			}
			// hostnamectl/timedatectl talk to systemd over D-Bus. Minimal
			// images (debootstrap minbase, some VPS templates) ship systemd
			// without a bus, and both fail with "Failed to connect to bus".
			return ensureOneOf([]string{"dbus", "dbus-broker"}, "dbus")
		},
	}
}

// ensureOneOf installs pkg unless one of the alternatives is already present.
func ensureOneOf(alternatives []string, pkg string) error {
	for _, alt := range alternatives {
		if pkgInstalled(alt) {
			return nil
		}
	}
	return aptInstall(pkg)
}

// Host probes, as variables so tests can provision "as" any distro on any
// machine.
var (
	hostOSRelease = system.ReadOSRelease
	pkgInstalled  = system.PkgInstalled
)

// aptEnvReady sets environment variables (inherited by every child process) so
// apt/dpkg never open an interactive prompt — the root cause of a spinner that
// hangs forever on Ubuntu 24.04 (needrestart's "restart services?" dialog).
func aptEnvReady() {
	if system.DryRun {
		return
	}
	os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	os.Setenv("NEEDRESTART_MODE", "a")    // auto-restart services, no prompt
	os.Setenv("NEEDRESTART_SUSPEND", "1") // suspend needrestart entirely
	os.Setenv("APT_LISTCHANGES_FRONTEND", "none")
}

// aptGet runs apt-get with a lock timeout, so a background apt-daily run on a
// freshly booted VM makes us wait (up to 5 min) instead of failing outright.
func aptGet(args ...string) (string, error) {
	aptEnvReady() // also for subcommands that run without preflight
	full := append([]string{"-o", "DPkg::Lock::Timeout=300"}, args...)
	return system.Run("apt-get", full...)
}

// aptInstall installs packages non-interactively, skipping ones already present.
func aptInstall(pkgs ...string) error {
	var missing []string
	for _, p := range pkgs {
		if !pkgInstalled(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	// force-conf* keeps existing config files without prompting on conflicts.
	args := []string{
		"install", "-y", "--no-install-recommends",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
	}
	args = append(args, missing...)
	_, err := aptGet(args...)
	return err
}
