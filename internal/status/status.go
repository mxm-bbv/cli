// Package status implements `forge status`: a one-glance, read-only summary of
// what forge configured on this host — containers, agent exposure, firewall,
// tailnet, alert timers and swap. It changes nothing.
package status

import (
	"os"
	"os/exec"
	"strings"

	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/ui"
)

// Run prints the summary and returns an exit code (always 0; it only reports).
func Run() int {
	ui.Println(ui.StyleTitle.Render("  forge status — " + hostname()))
	ui.Println()

	row := func(k, v string) { ui.Printf("  %s  %s\n", ui.StyleKey.Render(pad(k)), v) }

	// Docker + pinned images.
	if v := cmd("docker", "version", "--format", "{{.Server.Version}}"); v != "" {
		row("Docker:", v)
	} else {
		row("Docker:", ui.StyleWarn.Render("not installed / not running"))
	}
	agent, wt := steps.PinnedImages()

	// Portainer agent exposure.
	if binding := agentBinding(); binding != "" {
		note := ui.StyleOK.Render("tailnet/loopback only")
		if strings.HasPrefix(binding, "0.0.0.0:") || strings.HasPrefix(binding, ":::") {
			note = ui.StyleErr.Render("PUBLIC — exposed to the internet")
		}
		row("Portainer agent:", binding+"  "+note)
		if img := runningImage("portainer_agent"); img != "" && img != agent {
			row("", ui.StyleWarn.Render("image "+img+" ≠ pinned "+agent+" — run 'forge update images'"))
		}
	} else {
		row("Portainer agent:", ui.StyleMuted.Render("not installed"))
	}

	// Watchtower.
	if runningImage("watchtower") != "" {
		row("Watchtower:", "running (monitor-only)")
		if img := runningImage("watchtower"); img != wt {
			row("", ui.StyleWarn.Render("image "+img+" ≠ pinned "+wt+" — run 'forge update images'"))
		}
	}

	// Tailscale.
	if ts := cmd("tailscale", "ip", "-4"); ts != "" {
		row("Tailscale:", firstLine(ts)+"  "+ui.StyleOK.Render("up"))
	} else if has("tailscale") {
		row("Tailscale:", ui.StyleWarn.Render("installed but not connected"))
	}

	// Firewall.
	ufw := ui.StyleWarn.Render("inactive")
	if strings.Contains(cmd("ufw", "status"), "Status: active") {
		ufw = ui.StyleOK.Render("active")
	}
	dockerUser := ui.StyleWarn.Render("no DROP policy (containers bypass UFW)")
	if strings.Contains(cmd("iptables", "-S", "DOCKER-USER"), "DROP") {
		dockerUser = ui.StyleOK.Render("filtered")
	}
	row("Firewall:", "UFW "+ufw+"   DOCKER-USER "+dockerUser)

	// Alert timers.
	var timers []string
	for _, t := range []string{"forge-audit.timer", "forge-health.timer"} {
		if strings.TrimSpace(cmd("systemctl", "is-active", t)) == "active" {
			timers = append(timers, t)
		}
	}
	if len(timers) > 0 {
		row("Alerts:", ui.StyleOK.Render("active")+"  ("+strings.Join(timers, ", ")+")")
		if next := nextAudit(); next != "" {
			row("", ui.StyleMuted.Render("next audit: "+next))
		}
	} else {
		row("Alerts:", ui.StyleMuted.Render("not configured"))
	}

	// Swap.
	if sw := swap(); sw != "" {
		row("Swap:", sw)
	}

	ui.Println()
	ui.Println(ui.StyleMuted.Render("  deep scan: sudo forge audit    •    lint a compose file: forge lint <file>"))
	return 0
}

func agentBinding() string {
	out := cmd("docker", "inspect", "portainer_agent", "--format",
		`{{range $p, $c := .HostConfig.PortBindings}}{{range $c}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}`)
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	// Report the first 9001 binding; docker prints an empty HostIp for wildcard.
	for _, b := range strings.Fields(out) {
		if strings.Contains(b, "->9001") {
			if strings.HasPrefix(b, ":9001") || strings.HasPrefix(b, ":->") {
				return "0.0.0.0" + b
			}
			return b
		}
	}
	return firstLine(out)
}

func runningImage(name string) string {
	return strings.TrimSpace(cmd("docker", "inspect", name, "--format", "{{.Config.Image}}"))
}

func nextAudit() string {
	out := cmd("systemctl", "show", "forge-audit.timer", "--property=NextElapseUSecRealtime", "--value")
	return strings.TrimSpace(out)
}

func swap() string {
	out := cmd("swapon", "--show")
	if strings.TrimSpace(out) == "" {
		return ui.StyleMuted.Render("none")
	}
	return "enabled"
}

// --- helpers ---

func cmd(name string, args ...string) string {
	if !has(name) {
		return ""
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func has(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "server"
	}
	return h
}

func firstLine(s string) string {
	return strings.TrimSpace(strings.SplitN(strings.TrimSpace(s), "\n", 2)[0])
}

func pad(s string) string {
	const w = 16
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}
