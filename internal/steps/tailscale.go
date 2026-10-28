package steps

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

const (
	tailscaleKeyring = "/usr/share/keyrings/tailscale-archive-keyring.gpg"
	tailscaleList    = "/etc/apt/sources.list.d/tailscale.list"
)

// tailscaleStep installs Tailscale, the private network that keeps admin
// surfaces (Portainer Agent, emergency SSH) off the internet. Logging in is
// left to the operator (`forge tailscale`, which sets c.TailscaleLogin) unless
// an auth key makes it unattended.
func tailscaleStep() Step {
	return Step{
		Name: "Tailscale: private network for admin access",
		Skip: func(c *Context) bool {
			return !c.Cfg.InstallTailscale && !tailnetAgent(c.Cfg)
		},
		Run: func(c *Context) error {
			if !system.CommandExists("tailscale") {
				p, err := c.platform()
				if err != nil {
					return err
				}
				if err := installTailscale(p); err != nil {
					return err
				}
			}

			loggedIn := tailscaleUp()
			if !loggedIn {
				if strings.TrimSpace(c.Cfg.TailscaleAuthKey) == "" && !c.TailscaleLogin {
					c.Notes = append(c.Notes, "Tailscale is installed but not logged in. When you're ready:  sudo forge tailscale  (shows a QR code to scan)")
					return nil
				}
				if err := joinTailnet(c); err != nil {
					return err
				}
			}

			ip, err := tailnetIP()
			if err != nil {
				return err
			}
			c.TailnetIP = ip
			if !loggedIn && strings.TrimSpace(c.Cfg.TailscaleAuthKey) == "" {
				// A browser-approved machine belongs to the user, so its node
				// key expires (180 days by default) and it silently drops off
				// the tailnet — taking phone access to Portainer with it.
				c.Notes = append(c.Notes, "Tailscale: disable key expiry for "+system.Hostname()+
					" at https://login.tailscale.com/admin/machines (⋯ → Disable key expiry), otherwise it leaves the tailnet in ~180 days")
			}
			if c.TailscaleLogin && !c.Cfg.SSHTailnetOnly {
				c.Notes = append(c.Notes, fmt.Sprintf("Optional: SSH only over Tailscale. Reconnect with  ssh -p %d %s@%s  and run  sudo forge ssh tailnet-only",
					currentSSHPorts()[0], c.Cfg.Username, ip))
			}
			note := "Tailscale connected — tailnet IP " + ip
			if c.Cfg.TailscaleSSH {
				note += "; Tailscale SSH is on (emergency access from any tailnet device, e.g. your phone)"
			}
			c.Notes = append(c.Notes, note)
			return nil
		},
	}
}

// tailnetAgent reports whether the Portainer Agent is to ride the tailnet.
func tailnetAgent(cfg config.Config) bool {
	return cfg.InstallPortainer && cfg.PortainerAccess == config.PortainerTailnet
}

// tailscaleLoginURLRe finds the login link `tailscale up` prints.
var tailscaleLoginURLRe = regexp.MustCompile(`https://\S+`)

// joinTailnet runs `tailscale up`. With an auth key it is unattended. Without
// one it uses Tailscale's browser login: `tailscale up` prints a link and waits
// until someone signs in (Google, GitHub, Microsoft, …) and approves the
// machine — no keys that expire after a few days. The link is shown in the
// runner with a QR code so it can be approved from a phone.
func joinTailnet(c *Context) error {
	key := strings.TrimSpace(c.Cfg.TailscaleAuthKey)
	args, logline := []string{"up"}, "tailscale up"
	if key != "" {
		args = append(args, "--auth-key="+key)
		logline += " --auth-key=<hidden>"
	}
	if c.Cfg.TailscaleSSH {
		args = append(args, "--ssh")
		logline += " --ssh"
	}
	if key != "" {
		_, err := system.RunRedacted(logline, "tailscale", args...)
		return err
	}

	defer system.SetAttention(nil)
	_, err := system.RunWatch(logline, watchTailscaleLogin, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("Tailscale login was not completed — press r for a fresh link: %w", err)
	}
	return nil
}

// watchTailscaleLogin turns the login link in `tailscale up` output into an
// operator action (the runner shows it with a QR code).
func watchTailscaleLogin(line string) {
	if u := tailscaleLoginURLRe.FindString(line); u != "" {
		system.SetAttention(&system.Attention{
			Title: "Add this server to your Tailscale network",
			URL:   u,
			Hint:  "Scan the QR code with your phone (or open the link), sign in to Tailscale and approve. forge continues by itself.",
		})
	}
}

// installTailscale adds Tailscale's apt repo (fingerprint-verified, fail-closed)
// and installs the package — mirroring the Docker install's trust model.
// Derivatives (Mint, Pop!_OS, …) use the Ubuntu/Debian release they are built
// on — Tailscale publishes repos only for the upstream codenames.
func installTailscale(p system.Platform) error {
	if !system.FileExists(tailscaleKeyring) {
		url := fmt.Sprintf("https://pkgs.tailscale.com/stable/%s/%s.noarmor.gpg", p.Family, p.Codename)
		if _, err := system.Run("curl", "-fsSL", url, "-o", tailscaleKeyring); err != nil {
			return fmt.Errorf("Tailscale has no apt repo for %s (%s): %w", p, url, err)
		}
		if err := verifyKeyFingerprint(tailscaleKeyring, tailscaleGPGFingerprint, "Tailscale"); err != nil {
			return err
		}
	}
	repoLine := fmt.Sprintf("deb [signed-by=%s] https://pkgs.tailscale.com/stable/%s %s main",
		tailscaleKeyring, p.Family, p.Codename)
	if err := system.WriteFile(tailscaleList, repoLine+"\n", 0o644); err != nil {
		return err
	}
	if _, err := aptGet("update", "-y"); err != nil {
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
