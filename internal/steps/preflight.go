package steps

import (
	"fmt"
	"os"

	"github.com/mxm-bbv/cli/internal/system"
)

func preflightStep() Step {
	return Step{
		Name: "Preflight: apt update & sanity checks",
		Skip: always,
		Run: func(c *Context) error {
			rel := system.ReadOSRelease()
			if !rel.IsDebianLike() {
				return fmt.Errorf("unsupported OS %q — only Ubuntu/Debian are supported", rel.Pretty)
			}
			// Make every apt/dpkg invocation fully non-interactive so a hidden
			// needrestart/debconf prompt can never freeze the wizard.
			aptEnvReady()
			if _, err := aptGet("update", "-y"); err != nil {
				return err
			}
			// Tooling needed by later steps.
			return aptInstall("ca-certificates", "curl", "gnupg", "lsb-release")
		},
	}
}

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
}

// aptGet runs apt-get with a lock timeout, so a background apt-daily run on a
// freshly booted VM makes us wait (up to 5 min) instead of failing outright.
func aptGet(args ...string) (string, error) {
	full := append([]string{"-o", "DPkg::Lock::Timeout=300"}, args...)
	return system.Run("apt-get", full...)
}

// aptInstall installs packages non-interactively, skipping ones already present.
func aptInstall(pkgs ...string) error {
	var missing []string
	for _, p := range pkgs {
		if !system.PkgInstalled(p) {
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
