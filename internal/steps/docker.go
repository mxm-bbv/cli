package steps

import (
	"fmt"

	"github.com/mxm-bbv/cli/internal/system"
)

func dockerStep() Step {
	return Step{
		Name: "Docker Engine + Compose V2 + Buildx (official repo)",
		Skip: func(c *Context) bool {
			// Skip only if both docker and the compose plugin are present.
			if !system.CommandExists("docker") {
				return false
			}
			out, err := system.Run("docker", "compose", "version")
			return err == nil && out != ""
		},
		Run: func(c *Context) error {
			os := system.ReadOSRelease()
			repoOS := os.ID // "ubuntu" or "debian"
			if !os.IsDebianLike() {
				return fmt.Errorf("docker install: unsupported distro %q", os.ID)
			}

			// 1. Keyring for the Docker apt repo.
			if _, err := system.Run("install", "-m", "0755", "-d", "/etc/apt/keyrings"); err != nil {
				return err
			}
			if !system.FileExists("/etc/apt/keyrings/docker.asc") {
				url := fmt.Sprintf("https://download.docker.com/linux/%s/gpg", repoOS)
				// curl via exec (no shell) — the URL is fixed, but keep it uniform.
				if _, err := system.Run("curl", "-fsSL", url, "-o", "/etc/apt/keyrings/docker.asc"); err != nil {
					return err
				}
				// Refuse to proceed unless the key matches Docker's pinned fingerprint.
				if err := verifyDockerKey("/etc/apt/keyrings/docker.asc"); err != nil {
					return err
				}
				if _, err := system.Run("chmod", "a+r", "/etc/apt/keyrings/docker.asc"); err != nil {
					return err
				}
			}

			// 2. Apt source.
			repoLine := fmt.Sprintf(
				`deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable`,
				system.Arch(), repoOS, os.Codename,
			)
			if err := system.WriteFile("/etc/apt/sources.list.d/docker.list", repoLine+"\n", 0o644); err != nil {
				return err
			}

			// 3. Install packages.
			if _, err := system.Run("apt-get", "update", "-y"); err != nil {
				return err
			}
			if err := aptInstall(
				"docker-ce", "docker-ce-cli", "containerd.io",
				"docker-buildx-plugin", "docker-compose-plugin",
			); err != nil {
				return err
			}

			// 4. Enable & start.
			if _, err := system.Run("systemctl", "enable", "--now", "docker"); err != nil {
				return err
			}
			return nil
		},
	}
}

// daemonJSON: log rotation plus daemon-wide hardening.
//   - no-new-privileges: every container is denied setuid escalation by
//     default (not just the ones forge starts);
//   - live-restore: containers survive dockerd restarts/upgrades.
const daemonJSON = `{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "no-new-privileges": true,
  "live-restore": true
}
`

func logRotationStep() Step {
	return Step{
		Name: "Docker daemon hardening + log rotation (daemon.json)",
		Skip: func(c *Context) bool {
			return !c.Cfg.EnableLogRotation ||
				system.FileContains("/etc/docker/daemon.json", "no-new-privileges")
		},
		Run: func(c *Context) error {
			if _, err := system.Run("install", "-m", "0755", "-d", "/etc/docker"); err != nil {
				return err
			}
			system.BackupFile("/etc/docker/daemon.json")
			if err := system.WriteFile("/etc/docker/daemon.json", daemonJSON, 0o644); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "restart", "docker"); err != nil {
				return err
			}
			return nil
		},
	}
}
