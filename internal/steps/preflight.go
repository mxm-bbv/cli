package steps

import (
	"fmt"

	"github.com/mxm-bbv/cli/internal/system"
)

func preflightStep() Step {
	return Step{
		Name: "Preflight: apt update & sanity checks",
		Skip: always,
		Run: func(c *Context) error {
			os := system.ReadOSRelease()
			if !os.IsDebianLike() {
				return fmt.Errorf("unsupported OS %q — only Ubuntu/Debian are supported", os.Pretty)
			}
			if _, err := system.Run("apt-get", "update", "-y"); err != nil {
				return err
			}
			// Tooling needed by later steps.
			return aptInstall("ca-certificates", "curl", "gnupg", "lsb-release")
		},
	}
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
	args := append([]string{"install", "-y", "--no-install-recommends"}, missing...)
	_, err := system.Run("apt-get", args...)
	return err
}
