package steps

import (
	"fmt"
	"strconv"

	"github.com/mxm-bbv/cli/internal/config"
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
			port := sshPort(c.Cfg.SSHPort)
			// Default policy.
			if _, err := system.Run("ufw", "default", "deny", "incoming"); err != nil {
				return err
			}
			if _, err := system.Run("ufw", "default", "allow", "outgoing"); err != nil {
				return err
			}
			// Allow SSH FIRST so enabling UFW can't lock us out — both the
			// target port and every port sshd listens on right now. sshd only
			// moves to a new port in the very last step; until then the old
			// port must stay reachable (the hardening step closes it once the
			// new one is verified).
			rules := []string{fmt.Sprintf("%d/tcp", port)}
			for _, p := range currentSSHPorts() {
				if p != port {
					rules = append(rules, fmt.Sprintf("%d/tcp", p))
				}
			}
			rules = append(rules, "80/tcp", "443/tcp")
			for _, rule := range rules {
				if _, err := system.Run("ufw", "allow", rule); err != nil {
					return err
				}
			}
			// Tailnet mode: trust the tailscale interface (host services like
			// sshd stay reachable from your devices) and let WireGuard take
			// direct connections instead of falling back to relays.
			if c.Cfg.InstallPortainer && c.Cfg.PortainerAccess == config.PortainerTailnet {
				if _, err := system.Run("ufw", "allow", "in", "on", "tailscale0"); err != nil {
					return err
				}
				if _, err := system.Run("ufw", "allow", "41641/udp"); err != nil {
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

// sshPort normalises the configured SSH port (0 means the default 22).
func sshPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

// dockerUserFirewallStep closes the classic Docker/UFW hole: ports published
// with `-p` traverse the FORWARD chain (DOCKER-USER), never UFW's INPUT rules,
// so `ufw default deny incoming` silently does NOT apply to containers. This
// installs a persistent DOCKER-USER policy: external traffic reaches
// containers only on explicitly allowed ports.
func dockerUserFirewallStep() Step {
	return Step{
		Name: "Container firewall: DOCKER-USER rules (docker can't bypass UFW)",
		Skip: func(c *Context) bool { return !c.Cfg.EnableFirewall },
		Run: func(c *Context) error {
			public9001 := c.Cfg.InstallPortainer && c.Cfg.PortainerAccess == config.PortainerPublic
			if _, err := system.Run("install", "-m", "0755", "-d", "/usr/local/lib/forge"); err != nil {
				return err
			}
			if err := system.WriteFile(dockerUserScriptPath, dockerUserScript(public9001), 0o755); err != nil {
				return err
			}
			if err := system.WriteFile(dockerUserUnitPath, dockerUserUnit, 0o644); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "enable", "forge-docker-user.service"); err != nil {
				return err
			}
			// restart (not start): re-applies the rules when the policy changed.
			if _, err := system.Run("systemctl", "restart", "forge-docker-user.service"); err != nil {
				return err
			}
			c.Notes = append(c.Notes, "DOCKER-USER firewall active — containers accept external traffic only on 80/443"+map[bool]string{true: "/9001", false: ""}[public9001])
			return nil
		},
	}
}

const (
	dockerUserScriptPath = "/usr/local/lib/forge/docker-user.sh"
	dockerUserUnitPath   = "/etc/systemd/system/forge-docker-user.service"
)

// dockerUserScript renders the iptables policy. Notes:
//   - --dport here matches the CONTAINER port: DNAT happens before DOCKER-USER,
//     so publish containers on matching ports (80:80, 443:443).
//   - traffic arriving on tailscale0 is always allowed (admin plane);
//   - RFC1918 sources cover container-originated traffic through the bridges;
//   - inbound UDP to containers is dropped by default — add a RETURN rule here
//     if you ever publish a UDP service.
func dockerUserScript(public9001 bool) string {
	extra := ""
	if public9001 {
		extra = "$T -A DOCKER-USER -p tcp --dport 9001 -j RETURN\n"
	}
	return `#!/bin/sh
# Managed by forge — do not edit; rerun forge to regenerate.
set -e

# policy <iptables|ip6tables> <private source ranges…>
policy() {
T=$1; shift
$T -N DOCKER-USER 2>/dev/null || true
$T -F DOCKER-USER
$T -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
$T -A DOCKER-USER -i tailscale0 -j RETURN
for net in "$@"; do $T -A DOCKER-USER -s "$net" -j RETURN; done
$T -A DOCKER-USER -p tcp --dport 80 -j RETURN
$T -A DOCKER-USER -p tcp --dport 443 -j RETURN
` + extra + `$T -A DOCKER-USER -p tcp --syn -j DROP
$T -A DOCKER-USER -p udp -m conntrack --ctstate NEW -j DROP
$T -A DOCKER-USER -j RETURN
}

policy iptables 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
# IPv6: only when Docker manages ip6tables (the default since Engine 27) —
# otherwise there is no IPv6 forwarding to containers to filter.
if command -v ip6tables >/dev/null 2>&1 && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
  policy ip6tables fc00::/7 fe80::/10
fi
`
}

const dockerUserUnit = `[Unit]
Description=forge: DOCKER-USER firewall (containers respect the firewall)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
ExecStart=` + dockerUserScriptPath + `
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

// fail2banJail reads sshd's log from the systemd journal. The default
// ("auto") backend tails /var/log/auth.log, which doesn't exist on Debian 12+
// and other journald-only systems without rsyslog — the jail then refuses to
// start ("Have not found any log file for sshd jail"). The journal exists on
// every systemd distro forge supports.
const fail2banJail = `[sshd]
enabled  = true
backend  = systemd
port     = %s
maxretry = 5
bantime  = 1h
findtime = 10m
`

func fail2banStep() Step {
	return Step{
		Name: "fail2ban: SSH brute-force protection",
		Skip: func(c *Context) bool { return !c.Cfg.EnableFirewall },
		Run: func(c *Context) error {
			// python3-systemd is only a Recommends of fail2ban, and forge
			// installs with --no-install-recommends — but the systemd backend
			// needs it.
			if err := aptInstall("fail2ban", "python3-systemd"); err != nil {
				return err
			}
			jail := fmt.Sprintf(fail2banJail, strconv.Itoa(sshPort(c.Cfg.SSHPort)))
			if err := system.WriteFile("/etc/fail2ban/jail.d/sshd.local", jail, 0o644); err != nil {
				return err
			}
			// Validate before (re)starting so a bad jail fails loudly here
			// instead of leaving fail2ban silently dead.
			if _, err := system.Run("fail2ban-client", "-t"); err != nil {
				return fmt.Errorf("fail2ban rejected its configuration: %w", err)
			}
			if _, err := system.Run("systemctl", "enable", "fail2ban"); err != nil {
				return err
			}
			if _, err := system.Run("systemctl", "restart", "fail2ban"); err != nil {
				return err
			}
			return nil
		},
	}
}
