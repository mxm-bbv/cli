package steps

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

func sshHardeningStep() Step {
	return Step{
		Name: "SSH hardening: disable root / passwords, restart sshd",
		Skip: func(c *Context) bool {
			return !c.Cfg.DisableRootLogin && !c.Cfg.DisablePassauth && c.Cfg.SSHPort == 22
		},
		Run: func(c *Context) error {
			cfg := c.Cfg
			if err := system.BackupFile(sshdConfigPath); err != nil {
				return err
			}

			opts := map[string]string{
				"AllowUsers":                      cfg.Username,
				"PubkeyAuthentication":            "yes",
				"ChallengeResponseAuthentication": "no",
				"UsePAM":                          "yes",
			}
			if cfg.DisableRootLogin {
				opts["PermitRootLogin"] = "no"
			}
			if cfg.DisablePassauth {
				opts["PasswordAuthentication"] = "no"
				opts["KbdInteractiveAuthentication"] = "no"
			}
			if cfg.SSHPort != 22 && cfg.SSHPort > 0 {
				opts["Port"] = fmt.Sprintf("%d", cfg.SSHPort)
			}

			content, err := readFileOrEmpty(sshdConfigPath)
			if err != nil {
				return err
			}
			for k, v := range opts {
				content = setSSHDOption(content, k, v)
			}
			if err := system.WriteFile(sshdConfigPath, content, 0o644); err != nil {
				return err
			}

			// Validate before restarting — never lock ourselves out on a typo.
			if _, err := system.Run("sshd", "-t"); err != nil {
				return fmt.Errorf("sshd config validation failed, NOT restarting: %w", err)
			}
			if _, err := system.Run("systemctl", "restart", sshServiceName()); err != nil {
				return err
			}
			c.Notes = append(c.Notes, "sshd restarted — keep this session open and verify key login in a NEW terminal")
			return nil
		},
	}
}

// setSSHDOption replaces an existing (possibly commented) directive or appends a
// new one, ensuring exactly one active line for the key.
func setSSHDOption(content, key, value string) string {
	line := key + " " + value
	re := regexp.MustCompile(`(?m)^[#\s]*` + regexp.QuoteMeta(key) + `\s+.*$`)
	if re.MatchString(content) {
		return re.ReplaceAllString(content, line)
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
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
