package steps

import (
	"fmt"
	"os"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

func sshKeysStep() Step {
	return Step{
		Name: "SSH keys: authorized_keys + GitHub deploy key",
		Skip: always,
		Run: func(c *Context) error {
			cfg := c.Cfg
			home := cfg.HomeDir()
			sshDir := home + "/.ssh"

			if _, err := system.Run("install", "-d", "-m", "700", "-o", cfg.Username, "-g", cfg.Username, sshDir); err != nil {
				return err
			}

			// 1. Import the admin public key into authorized_keys (login access).
			if cfg.AdminKeySource != config.AdminKeySkip {
				key, err := resolveAdminKey(cfg)
				if err != nil {
					return err
				}
				if key != "" {
					fields := strings.Fields(key)
					if len(fields) < 2 {
						return fmt.Errorf("admin key does not look like a valid SSH public key")
					}
					ak := sshDir + "/authorized_keys"
					if !system.FileContains(ak, fields[1]) {
						if err := appendLine(ak, key); err != nil {
							return err
						}
					}
					c.AdminKeyInstalled = true
				}
			}
			if hasAuthorizedKey(sshDir + "/authorized_keys") {
				c.AdminKeyInstalled = true
			}

			// 2. Generate an ed25519 key for cloning private GitHub repos.
			if cfg.GenerateGitHubKey {
				keyPath := sshDir + "/id_ed25519"
				if !system.FileExists(keyPath) {
					if _, err := system.Run("runuser", "-u", cfg.Username, "--",
						"ssh-keygen", "-t", "ed25519", "-C", cfg.GitHubKeyComment, "-f", keyPath, "-N", ""); err != nil {
						return err
					}
				}
				if pub, err := os.ReadFile(keyPath + ".pub"); err == nil {
					c.GitHubPubKey = strings.TrimSpace(string(pub))
				} else if system.DryRun {
					c.GitHubPubKey = "<generated on real run — paste into GitHub → Deploy keys>"
				}

				// 3. known_hosts for github.com — verified against the pinned FP.
				kh := sshDir + "/known_hosts"
				if !system.FileContains(kh, "github.com") {
					entry, err := verifiedGitHubHostKey()
					if err != nil {
						return err
					}
					if err := appendLine(kh, entry); err != nil {
						return err
					}
				}

				// 4. ~/.ssh/config entry for github.com.
				cfgPath := sshDir + "/config"
				if !system.FileContains(cfgPath, "Host github.com") {
					entry := "Host github.com\n    User git\n    IdentityFile ~/.ssh/id_ed25519\n    IdentitiesOnly yes\n"
					if err := appendLine(cfgPath, entry); err != nil {
						return err
					}
				}
			}

			// Lock down ownership and permissions on the whole .ssh dir.
			if _, err := system.Run("chown", "-R", cfg.Username+":"+cfg.Username, sshDir); err != nil {
				return err
			}
			_, _ = system.RunShell(fmt.Sprintf("chmod 600 %s/authorized_keys %s/known_hosts %s/config %s/id_ed25519 2>/dev/null; chmod 644 %s/id_ed25519.pub 2>/dev/null; true", sshDir, sshDir, sshDir, sshDir, sshDir))
			return nil
		},
	}
}

// resolveAdminKey turns the configured source into a public key string.
func resolveAdminKey(cfg config.Config) (string, error) {
	switch cfg.AdminKeySource {
	case config.AdminKeyPaste:
		return strings.TrimSpace(cfg.AdminKeyValue), nil
	case config.AdminKeyFile:
		data, err := os.ReadFile(cfg.AdminKeyValue)
		if err != nil {
			return "", fmt.Errorf("read admin key file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	case config.AdminKeyGitHub:
		user := strings.TrimSpace(cfg.AdminKeyValue)
		if !githubUserRe.MatchString(user) {
			return "", fmt.Errorf("%q is not a valid GitHub username", user)
		}
		out, err := system.Run("curl", "-fsSL", "https://github.com/"+user+".keys")
		if err != nil {
			return "", fmt.Errorf("fetch github keys for %q: %w", user, err)
		}
		if strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("github.com/%s.keys returned no keys — is your public key added to that account?", user)
		}
		return strings.TrimSpace(out), nil
	default:
		return "", nil
	}
}

// appendLine appends a line to a file, creating it if necessary. Honours dry-run.
func appendLine(path, line string) error {
	system.CommandLog = append(system.CommandLog, fmt.Sprintf("append -> %s", path))
	if system.DryRun {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, err = f.WriteString(line)
	return err
}
