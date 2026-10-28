package steps

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// Closing SSH to the internet leaves Tailscale as the only way in (plus the
// provider's web console), so `forge ssh tailnet-only` only proceeds once it
// is proven to work: the operator must be connected over the tailnet right
// now, and the node key must not be set to expire — an expired key drops the
// box off the tailnet, and with it the last door.

// tailnetNets are Tailscale's address ranges: its CGNAT IPv4 block and IPv6 ULA prefix.
var tailnetNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"} {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

// IsTailnetIP reports whether ip belongs to a tailnet.
func IsTailnetIP(ip string) bool {
	p := net.ParseIP(strings.Trim(ip, "[]"))
	if p == nil {
		return false
	}
	for _, n := range tailnetNets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// SessionClient returns the client address of the SSH session this process
// runs in: SSH_CONNECTION of the nearest ancestor that has it (sudo strips it
// from its own environment, the login shell above it still has it).
func SessionClient() string {
	for pid := os.Getpid(); pid > 1; {
		if env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
			for _, kv := range strings.Split(string(env), "\x00") {
				if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
					client, _, _ := strings.Cut(v, " ")
					return client
				}
			}
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return ""
		}
		// Fields after the ")" that ends the command name: state, ppid, …
		_, rest, _ := strings.Cut(string(stat), ") ")
		f := strings.Fields(rest)
		if len(f) < 2 {
			return ""
		}
		if pid, err = strconv.Atoi(f[1]); err != nil {
			return ""
		}
	}
	return ""
}

// tailscaleKeyExpiry returns when this node's key expires, or "" if it never
// does (key expiry disabled in the admin console, or a tagged node).
func tailscaleKeyExpiry() (string, error) {
	out, err := system.Output("tailscale", "status", "--json")
	if err != nil {
		return "", errors.New("Tailscale isn't running — log in first: sudo forge tailscale")
	}
	var st struct {
		BackendState string
		Self         struct {
			KeyExpiry string
		}
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	if st.BackendState != "Running" {
		return "", errors.New("Tailscale isn't connected — log in first: sudo forge tailscale")
	}
	return st.Self.KeyExpiry, nil
}

// CheckTailnetOnly verifies that closing SSH to the internet can't lock the
// operator out, and returns the tailnet address to use from now on.
func CheckTailnetOnly() (string, error) {
	if !system.CommandExists("ufw") || strings.TrimSpace(firstLineOf(system.Output("ufw", "status"))) != "Status: active" {
		return "", errors.New("UFW isn't active — the firewall decides who reaches SSH, enable it with the forge setup first")
	}
	expiry, err := tailscaleKeyExpiry()
	if err != nil {
		return "", err
	}
	ip, err := tailnetIP()
	if err != nil {
		return "", err
	}
	if expiry != "" {
		return "", fmt.Errorf("this server's Tailscale key expires on %s — after that it drops off the tailnet and you'd be locked out.\n"+
			"  Disable key expiry first: https://login.tailscale.com/admin/machines → %s → ⋯ → Disable key expiry", expiry, system.Hostname())
	}
	if client := SessionClient(); !IsTailnetIP(client) {
		from := client
		if from == "" {
			from = "not over SSH"
		}
		return "", fmt.Errorf("you're connected from %s, not over Tailscale. Prove the tailnet way in works first —\n"+
			"  reconnect with  ssh -p %d <user>@%s  (or Tailscale SSH) and run this again", from, currentSSHPorts()[0], ip)
	}
	return ip, nil
}

// SetSSHTailnetOnly closes (on=true) or reopens sshd's ports to the internet
// in UFW. The tailscale0 interface stays trusted either way.
func SetSSHTailnetOnly(on bool) error {
	if _, err := system.Run("ufw", "allow", "in", "on", "tailscale0"); err != nil {
		return err
	}
	for _, p := range currentSSHPorts() {
		rule := fmt.Sprintf("%d/tcp", p)
		args := []string{"allow", rule}
		if on {
			args = []string{"delete", "allow", rule}
		}
		if _, err := system.Run("ufw", args...); err != nil {
			return err
		}
	}
	return nil
}

// SSHOpenToInternet reports whether UFW lets the internet reach sshd.
func SSHOpenToInternet() bool {
	out, _ := system.Output("ufw", "status")
	for _, p := range currentSSHPorts() {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && (f[0] == strconv.Itoa(p) || f[0] == strconv.Itoa(p)+"/tcp") && f[1] == "ALLOW" {
				return true
			}
		}
	}
	return false
}

func firstLineOf(s string, _ error) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
