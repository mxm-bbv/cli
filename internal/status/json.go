package status

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/tripwire"
)

// Report is `forge status --json`: what `forge status` shows, for a program
// to read (deploy.me over ssh). Facts only root can see are false or empty
// without it; Root says which it was.
type Report struct {
	V           int    `json:"v"`
	Forge       string `json:"forge"`
	Hostname    string `json:"hostname"`
	Root        bool   `json:"root"`
	Provisioned bool   `json:"provisioned"` // set up by forge (its answers are kept)
	Docker      string `json:"docker"`
	Agent       struct {
		Binding string `json:"binding"`
		Public  bool   `json:"public"`
		Image   string `json:"image"`
		Pinned  string `json:"pinned"`
	} `json:"agent"`
	Watchtower struct {
		Running bool   `json:"running"`
		Image   string `json:"image"`
		Pinned  string `json:"pinned"`
	} `json:"watchtower"`
	Tailscale struct {
		Installed bool   `json:"installed"`
		IP        string `json:"ip"`
	} `json:"tailscale"`
	Firewall struct {
		UFW        bool `json:"ufw"`
		DockerUser bool `json:"docker_user"`
	} `json:"firewall"`
	SSHTailnetOnly bool     `json:"ssh_tailnet_only"`
	Alerts         []string `json:"alerts"` // the alert timers that run
	// Alerting is where alerts go and which logins are said (forge ≥ 0.6;
	// readable as root only, like alerts.env).
	Alerting struct {
		Configured bool     `json:"configured"`
		Name       string   `json:"name"`
		Logins     string   `json:"logins"`
		Quiet      []string `json:"quiet"`
	} `json:"alerting"`
	NextAudit string `json:"next_audit"`
	Tripwire  bool   `json:"tripwire"`
	Swap      bool   `json:"swap"`
}

// Collect gathers the report. It changes nothing.
func Collect(version string) Report {
	var r Report
	r.V, r.Forge, r.Hostname, r.Root = 1, version, hostname(), os.Geteuid() == 0
	_, err := os.Stat(config.StatePath)
	r.Provisioned = err == nil

	r.Docker = strings.TrimSpace(cmd("docker", "version", "--format", "{{.Server.Version}}"))
	agent, wt := steps.PinnedImages()
	if binding := agentBinding(); binding != "" {
		r.Agent.Binding = binding
		r.Agent.Public = strings.HasPrefix(binding, "0.0.0.0:") || strings.HasPrefix(binding, ":::")
		r.Agent.Image = runningImage("portainer_agent")
	}
	r.Agent.Pinned = agent
	r.Watchtower.Image = runningImage("watchtower")
	r.Watchtower.Running = r.Watchtower.Image != ""
	r.Watchtower.Pinned = wt

	r.Tailscale.Installed = has("tailscale")
	r.Tailscale.IP = firstLine(cmd("tailscale", "ip", "-4"))

	r.Firewall.UFW = strings.Contains(cmd("ufw", "status"), "Status: active")
	r.Firewall.DockerUser = strings.Contains(cmd("iptables", "-S", "DOCKER-USER"), "DROP")
	r.SSHTailnetOnly = r.Root && !steps.SSHOpenToInternet()

	r.Alerts = []string{}
	for _, t := range []string{"forge-audit.timer", "forge-health.timer"} {
		if strings.TrimSpace(cmd("systemctl", "is-active", t)) == "active" {
			r.Alerts = append(r.Alerts, t)
		}
	}
	if len(r.Alerts) > 0 {
		r.NextAudit = nextAudit()
	}
	r.Alerting.Quiet = []string{}
	if set, ok := alerts.Load(); ok {
		r.Alerting.Configured, r.Alerting.Name, r.Alerting.Logins = set.Configured, set.Name, set.Logins
		for _, p := range set.Quiet {
			r.Alerting.Quiet = append(r.Alerting.Quiet, p.String())
		}
	}
	r.Tripwire = tripwire.Installed()
	r.Swap = strings.TrimSpace(cmd("swapon", "--show")) != ""
	return r
}

// RunJSON prints the report as one JSON object.
func RunJSON(version string) int {
	out, err := json.Marshal(Collect(version))
	if err != nil {
		return 1
	}
	fmt.Println(string(out))
	return 0
}
