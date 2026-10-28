package steps

import (
	"fmt"
	"os/user"

	"github.com/mxm-bbv/cli/internal/system"
)

func userStep() Step {
	return Step{
		Name: "Create deploy user with sudo + docker access",
		Skip: always, // the Run body is itself idempotent
		Run: func(c *Context) error {
			cfg := c.Cfg

			// Guard: the username flows into shell/exec commands elsewhere.
			if err := ValidUsername(cfg.Username); err != nil {
				return fmt.Errorf("invalid username %q: %w", cfg.Username, err)
			}

			// Create the user (with home + bash) if it doesn't exist.
			if !userExists(cfg.Username) {
				if _, err := system.Run("useradd", "-m", "-s", "/bin/bash", cfg.Username); err != nil {
					return err
				}
			}

			// Set the password (carried at runtime, never serialised).
			if cfg.DeployPassword != "" {
				if err := system.RunInput(cfg.Username+":"+cfg.DeployPassword, "chpasswd"); err != nil {
					return err
				}
			}

			// Grant sudo membership. The sudo package itself is installed by
			// preflight (minimal Debian has the group but not the binary).
			if _, err := system.Run("usermod", "-aG", "sudo", cfg.Username); err != nil {
				return err
			}
			// The docker group is created by the docker-ce package. If the
			// Docker step was skipped after a failure, don't fail here too.
			if !groupExists("docker") {
				c.Notes = append(c.Notes, "docker group missing (Docker step skipped?) — run `usermod -aG docker "+cfg.Username+"` after installing Docker")
				return nil
			}
			if _, err := system.Run("usermod", "-aG", "docker", cfg.Username); err != nil {
				return err
			}
			return nil
		},
	}
}

func groupExists(name string) bool {
	if system.DryRun {
		return true
	}
	_, err := user.LookupGroup(name)
	return err == nil
}

func userExists(name string) bool {
	if system.DryRun {
		return false
	}
	_, err := user.Lookup(name)
	return err == nil
}
