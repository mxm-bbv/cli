package steps

import (
	"os/user"

	"github.com/mxm-bbv/cli/internal/system"
)

func userStep() Step {
	return Step{
		Name: "Create deploy user with sudo + docker access",
		Skip: always, // the Run body is itself idempotent
		Run: func(c *Context) error {
			cfg := c.Cfg

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

			// Grant sudo and docker group membership.
			if _, err := system.Run("usermod", "-aG", "sudo", cfg.Username); err != nil {
				return err
			}
			// docker group exists only after the docker step; ignore failure
			// gracefully isn't possible here, so the docker group is guaranteed
			// because dockerStep runs earlier.
			if _, err := system.Run("usermod", "-aG", "docker", cfg.Username); err != nil {
				return err
			}
			return nil
		},
	}
}

func userExists(name string) bool {
	if system.DryRun {
		return false
	}
	_, err := user.Lookup(name)
	return err == nil
}
