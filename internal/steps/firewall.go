package steps

import (
	"fmt"

	"github.com/mxm-bbv/cli/internal/system"
)

func firewallStep() Step {
	return Step{
		Name: "UFW firewall: allow SSH/HTTP/HTTPS, enable",
		Skip: func(c *Context) bool { return !c.Cfg.EnableFirewall },
		Run: func(c *Context) error {
			if err := aptInstall("ufw"); err != nil {
				return err
			}
			port := c.Cfg.SSHPort
			if port == 0 {
				port = 22
			}
			// Default policy.
			if _, err := system.Run("ufw", "default", "deny", "incoming"); err != nil {
				return err
			}
			if _, err := system.Run("ufw", "default", "allow", "outgoing"); err != nil {
				return err
			}
			// Allow the SSH port FIRST so enabling UFW can't lock us out.
			for _, rule := range []string{fmt.Sprintf("%d/tcp", port), "80/tcp", "443/tcp"} {
				if _, err := system.Run("ufw", "allow", rule); err != nil {
					return err
				}
			}
			if _, err := system.Run("ufw", "--force", "enable"); err != nil {
				return err
			}
			return nil
		},
	}
}

const fail2banJail = `[sshd]
enabled = true
port    = %d
maxretry = 5
bantime = 1h
findtime = 10m
`

func fail2banStep() Step {
	return Step{
		Name: "fail2ban: SSH brute-force protection",
		Skip: func(c *Context) bool { return !c.Cfg.EnableFirewall },
		Run: func(c *Context) error {
			if err := aptInstall("fail2ban"); err != nil {
				return err
			}
			port := c.Cfg.SSHPort
			if port == 0 {
				port = 22
			}
			jail := fmt.Sprintf(fail2banJail, port)
			if err := system.WriteFile("/etc/fail2ban/jail.d/sshd.local", jail, 0o644); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "enable", "--now", "fail2ban"); err != nil {
				return err
			}
			_, _ = system.Run("systemctl", "restart", "fail2ban")
			return nil
		},
	}
}
