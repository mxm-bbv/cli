package steps

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

const (
	tailscaleKeyring = "/usr/share/keyrings/tailscale-archive-keyring.gpg"
	tailscaleList    = "/etc/apt/sources.list.d/tailscale.list"
)

// tailscaleStep joins the box to the user's tailnet so admin surfaces
// (Portainer Agent, emergency SSH) never have to be published to the internet.
func tailscaleStep() Step {
	return Step{
		Name: "Tailscale: private network for admin access",
		Skip: func(c *Context) bool {
			return !c.Cfg.InstallPortainer || c.Cfg.PortainerAccess != config.PortainerTailnet
		},
		Run: func(c *Context) error {
			if !system.CommandExists("tailscale") {
				if err := installTailscale(); err != nil {
					return err
				}
			}

			if !tailscaleUp() {
				key := strings.TrimSpace(c.Cfg.TailscaleAuthKey)
				if key == "" && !system.DryRun {
					return errors.New("this box has not joined your tailnet and no auth key was given — " +
						"create one at https://login.tailscale.com/admin/settings/keys and rerun, " +
						"or join manually with `tailscale up`")
				}
				args := []string{"up", "--auth-key=" + key}
				logline := "tailscale up --auth-key=<hidden>"
				if c.Cfg.TailscaleSSH {
					args = append(args, "--ssh")
					logline += " --ssh"
				}
				if _, err := system.RunRedacted(logline, "tailscale", args...); err != nil {
					return err
				}
			}

			ip, err := tailnetIP()
			if err != nil {
				return err
			}
			c.TailnetIP = ip
			note := "Tailscale joined — tailnet IP " + ip
			if c.Cfg.TailscaleSSH {
				note += "; Tailscale SSH is on (emergency access from any tailnet device, e.g. your phone)"
			}
			c.Notes = append(c.Notes, note)
			return nil
		},
	}
}

// installTailscale adds Tailscale's apt repo (fingerprint-verified, fail-closed)
// and installs the package — mirroring the Docker install's trust model.
func installTailscale() error {
	os := system.ReadOSRelease()
	if !system.FileExists(tailscaleKeyring) {
		url := fmt.Sprintf("https://pkgs.tailscale.com/stable/%s/%s.noarmor.gpg", os.ID, os.Codename)
		if _, err := system.Run("curl", "-fsSL", url, "-o", tailscaleKeyring); err != nil {
			return err
		}
		if err := verifyKeyFingerprint(tailscaleKeyring, tailscaleGPGFingerprint, "Tailscale"); err != nil {
			return err
		}
	}
	repoLine := fmt.Sprintf("deb [signed-by=%s] https://pkgs.tailscale.com/stable/%s %s main",
		tailscaleKeyring, os.ID, os.Codename)
	if err := system.WriteFile(tailscaleList, repoLine+"\n", 0o644); err != nil {
		return err
	}
	if _, err := system.Run("apt-get", "update", "-y"); err != nil {
		return err
	}
	return aptInstall("tailscale")
}

// tailscaleUp reports whether the box is already joined and running.
func tailscaleUp() bool {
	if system.DryRun {
		return false
	}
	out, err := system.Run("tailscale", "status", "--peers=false")
	return err == nil && !strings.Contains(out, "Logged out")
}

// tailnetIP returns the box's IPv4 address inside the tailnet.
func tailnetIP() (string, error) {
	out, err := system.Run("tailscale", "ip", "-4")
	if err != nil {
		return "", fmt.Errorf("tailscale ip: %w", err)
	}
	ip := strings.TrimSpace(strings.Split(out, "\n")[0])
	if ip == "" {
		if system.DryRun {
			return "<tailnet-ip>", nil
		}
		return "", errors.New("tailscale reported no IPv4 address — is the node approved in the admin console?")
	}
	return ip, nil
}
