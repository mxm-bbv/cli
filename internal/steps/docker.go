package steps

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

const (
	dockerKeyring     = "/etc/apt/keyrings/docker.asc"
	dockerList        = "/etc/apt/sources.list.d/docker.list"
	dockerSources     = "/etc/apt/sources.list.d/docker.sources" // deb822 form from Docker's current docs
	daemonJSONPath    = "/etc/docker/daemon.json"
	dockerRepoBaseURL = "https://download.docker.com/linux"
)

// dockerConflicts are distro packages that clash with docker-ce (Docker's
// documented "uninstall old versions" list). Removing them keeps images,
// containers and volumes in /var/lib/docker.
var dockerConflicts = []string{
	"docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
	"podman-docker", "containerd", "runc",
}

func dockerStep() Step {
	return Step{
		Name: "Docker Engine + Compose V2 + Buildx (official repo)",
		Skip: func(c *Context) bool {
			// A snap-packaged docker must reach Run, which explains the problem.
			if dockerIsSnap() {
				return false
			}
			// Skip only if both docker and the compose plugin are present.
			if !system.CommandExists("docker") {
				return false
			}
			out, err := system.Run("docker", "compose", "version")
			return err == nil && out != ""
		},
		Run: func(c *Context) error {
			if dockerIsSnap() {
				return errors.New("Docker is installed as a snap (Ubuntu installer option). forge manages the apt " +
					"docker-ce engine: the snap ignores /etc/docker/daemon.json and has no docker.service. " +
					"Back up your data, run `snap remove docker`, then rerun forge")
			}
			p, err := c.platform()
			if err != nil {
				return err
			}

			// 0. Fail early, with a useful message, when Docker doesn't
			//    publish packages for this release (new or testing codename).
			suite := fmt.Sprintf("%s/%s/dists/%s/Release", dockerRepoBaseURL, p.Family, p.Codename)
			if _, err := system.Run("curl", "-fsSIL", "-o", "/dev/null", suite); err != nil {
				return fmt.Errorf("Docker has no apt repo for %s yet (%s) — use a supported release "+
					"(Ubuntu 22.04/24.04/26.04, Debian 12/13): %w", p, suite, err)
			}

			// 1. Remove distro packages that conflict with docker-ce.
			var conflicts []string
			for _, pkg := range dockerConflicts {
				if pkgInstalled(pkg) {
					conflicts = append(conflicts, pkg)
				}
			}
			if len(conflicts) > 0 {
				if _, err := aptGet(append([]string{"remove", "-y"}, conflicts...)...); err != nil {
					return err
				}
				c.Notes = append(c.Notes, "removed distro Docker packages in favour of docker-ce: "+strings.Join(conflicts, ", ")+" (images and volumes kept)")
			}

			// 2. Keyring for the Docker apt repo.
			if _, err := system.Run("install", "-m", "0755", "-d", "/etc/apt/keyrings"); err != nil {
				return err
			}
			if !system.FileExists(dockerKeyring) {
				url := fmt.Sprintf("%s/%s/gpg", dockerRepoBaseURL, p.Family)
				// curl via exec (no shell) — the URL is fixed, but keep it uniform.
				if _, err := system.Run("curl", "-fsSL", url, "-o", dockerKeyring); err != nil {
					return err
				}
				// Refuse to proceed unless the key matches Docker's pinned fingerprint.
				if err := verifyDockerKey(dockerKeyring); err != nil {
					return err
				}
				if _, err := system.Run("chmod", "a+r", dockerKeyring); err != nil {
					return err
				}
			}

			// 3. Apt source — unless Docker's deb822 file already defines the
			//    same repo (apt warns about, or rejects, duplicate sources).
			if !system.FileExists(dockerSources) {
				repoLine := fmt.Sprintf(
					`deb [arch=%s signed-by=%s] %s/%s %s stable`,
					system.Arch(), dockerKeyring, dockerRepoBaseURL, p.Family, p.Codename,
				)
				if err := system.WriteFile(dockerList, repoLine+"\n", 0o644); err != nil {
					return err
				}
			}

			// 4. Install packages.
			if _, err := aptGet("update", "-y"); err != nil {
				return err
			}
			if err := aptInstall(
				"docker-ce", "docker-ce-cli", "containerd.io",
				"docker-buildx-plugin", "docker-compose-plugin",
			); err != nil {
				return err
			}

			// 5. Enable & start.
			if _, err := system.Run("systemctl", "enable", "--now", "docker"); err != nil {
				return err
			}
			return nil
		},
	}
}

// dockerIsSnap reports whether docker comes from the Ubuntu snap.
func dockerIsSnap() bool {
	if system.DryRun {
		return false
	}
	if system.FileExists("/snap/bin/docker") {
		return true
	}
	if !system.CommandExists("snap") {
		return false
	}
	_, err := system.Output("snap", "list", "docker")
	return err == nil
}

// daemonSettings is what forge enforces in daemon.json:
//   - no-new-privileges: every container is denied setuid escalation by
//     default (not just the ones forge starts);
//   - live-restore: containers survive dockerd restarts/upgrades.
//
// Log rotation (json-file, 10m × 3) is added only when no log driver is
// configured — an existing journald/local/… choice is the operator's.
var daemonSettings = map[string]any{
	"no-new-privileges": true,
	"live-restore":      true,
}

var daemonLogSettings = map[string]any{
	"log-driver": "json-file",
	"log-opts":   map[string]any{"max-size": "10m", "max-file": "3"},
}

// mergeDaemonJSON overlays forge's settings onto an existing daemon.json,
// keeping everything else (registry mirrors, address pools, …). Invalid JSON
// is an error — forge never clobbers a file it cannot understand.
func mergeDaemonJSON(existing []byte) ([]byte, error) {
	cfg := map[string]any{}
	if len(strings.TrimSpace(string(existing))) > 0 {
		if err := json.Unmarshal(existing, &cfg); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON (%v) — fix or remove it, then rerun", daemonJSONPath, err)
		}
	}
	for k, v := range daemonSettings {
		cfg[k] = v
	}
	if _, ok := cfg["log-driver"]; !ok {
		for k, v := range daemonLogSettings {
			cfg[k] = v
		}
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func logRotationStep() Step {
	return Step{
		Name: "Docker daemon hardening + log rotation (daemon.json)",
		Skip: func(c *Context) bool {
			return !c.Cfg.EnableLogRotation ||
				system.FileContains(daemonJSONPath, "no-new-privileges")
		},
		Run: func(c *Context) error {
			if _, err := system.Run("install", "-m", "0755", "-d", "/etc/docker"); err != nil {
				return err
			}
			existing, err := readFileOrEmpty(daemonJSONPath)
			if err != nil {
				return err
			}
			merged, err := mergeDaemonJSON([]byte(existing))
			if err != nil {
				return err
			}
			if err := system.BackupFile(daemonJSONPath); err != nil {
				return err
			}
			if err := system.WriteFile(daemonJSONPath, string(merged), 0o644); err != nil {
				return err
			}
			// Validate before restarting: a daemon.json dockerd rejects means
			// docker won't come back up. Engines older than 23 lack --validate.
			if out, err := system.Run("dockerd", "--validate", "--config-file", daemonJSONPath); err != nil &&
				!strings.Contains(out, "unknown flag") {
				_ = restoreFile(daemonJSONPath, existing)
				return fmt.Errorf("dockerd rejected the merged daemon.json (restored the previous one): %w", err)
			}
			if _, err := system.Run("systemctl", "restart", "docker"); err != nil {
				return err
			}
			return nil
		},
	}
}

// restoreFile puts previous content back (or removes the file if there was
// none). Used to roll back a config that failed validation.
func restoreFile(path, previous string) error {
	if previous == "" {
		return system.RemoveFile(path)
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	return system.WriteFile(path, previous, mode)
}
