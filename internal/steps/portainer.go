package steps

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

func portainerStep() Step {
	return Step{
		Name: "Portainer Agent",
		Skip: func(c *Context) bool { return !c.Cfg.InstallPortainer },
		Run: func(c *Context) error {
			// Where the agent listens. Access to the agent is root-equivalent
			// (it holds the docker socket), so it must never sit on 0.0.0.0
			// unprotected — an unauthenticated public agent on :9001 is a
			// known, actively scanned compromise vector.
			bindIP := ""
			if c.Cfg.PortainerAccess == config.PortainerTailnet {
				if c.TailnetIP == "" {
					if !system.DryRun {
						return errors.New("tailnet mode but no tailnet IP — the Tailscale step must run first")
					}
					c.TailnetIP = "<tailnet-ip>"
				}
				bindIP = c.TailnetIP
			}
			publish := "9001:9001"
			if bindIP != "" {
				publish = bindIP + ":9001:9001"
			}

			// If an agent already exists, keep it only when its binding is
			// already what we want AND it has a secret; otherwise replace it —
			// re-running forge on an old box must fix an insecure agent.
			if containerExists("portainer_agent") {
				hostIP, secret := inspectAgent()
				if hostIP == bindIP && secret != "" {
					c.AgentSecret = secret
					c.Notes = append(c.Notes, "Portainer Agent already bound to "+publish+" with a secret — left as is")
					return nil
				}
				if _, err := system.Run("docker", "rm", "-f", "portainer_agent"); err != nil {
					return err
				}
				c.Notes = append(c.Notes, "Old Portainer Agent removed (insecure or stale binding) and re-created")
			}

			// AGENT_SECRET: without it, ANY Portainer server that can reach the
			// port can pair with the agent. The value is passed via the
			// environment (`-e AGENT_SECRET` with no value), so it never
			// appears in the docker command line or the forge command log.
			if c.AgentSecret == "" {
				c.AgentSecret = randomHex(16)
			}
			// No "-v /:/host": that exposes the entire host filesystem to the
			// container. Basic agent operation doesn't need it. no-new-privileges
			// blocks setuid-based privilege escalation inside the container.
			_, err := system.RunEnv([]string{"AGENT_SECRET=" + c.AgentSecret},
				"docker", "run", "-d",
				"-p", publish,
				"--name", "portainer_agent",
				"--restart=always",
				"--security-opt", "no-new-privileges",
				"-e", "AGENT_SECRET",
				"-v", "/var/run/docker.sock:/var/run/docker.sock",
				"-v", "/var/lib/docker/volumes:/var/lib/docker/volumes",
				portainerAgentImage,
			)
			if err == nil {
				where := "tailnet-only, invisible to the internet"
				if bindIP == "" {
					where = "PUBLIC — allowed through DOCKER-USER; consider tailnet mode instead"
				}
				c.Notes = append(c.Notes, "Portainer Agent ("+portainerAgentImage+") on "+publish+" ("+where+")")
			}
			return err
		},
	}
}

// inspectAgent returns the existing agent's published host IP for 9001 and its
// AGENT_SECRET (empty when unset), so a rerun can keep a correctly-secured
// agent instead of rotating its secret.
func inspectAgent() (hostIP, secret string) {
	out, err := system.Run("docker", "inspect", "portainer_agent",
		"--format", `{{(index (index .HostConfig.PortBindings "9001/tcp") 0).HostIp}}|{{range .Config.Env}}{{println .}}{{end}}`)
	if err != nil {
		return "", ""
	}
	ipPart, envPart, _ := strings.Cut(out, "|")
	hostIP = strings.TrimSpace(ipPart)
	if hostIP == "0.0.0.0" { // docker reports an explicit wildcard as 0.0.0.0
		hostIP = ""
	}
	for _, l := range strings.Split(envPart, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "AGENT_SECRET="); ok {
			secret = v
		}
	}
	return hostIP, secret
}

func watchtowerStep() Step {
	return Step{
		Name: "Watchtower (monitor-only update checks)",
		Skip: func(c *Context) bool {
			return !c.Cfg.InstallWatchtower || containerExists("watchtower")
		},
		Run: func(c *Context) error {
			// --monitor-only: Watchtower holds the docker socket, so letting it
			// auto-replace containers with whatever a registry serves is a
			// supply-chain risk. It only reports; you update deliberately.
			_, err := system.Run("docker", "run", "-d",
				"--name", "watchtower",
				"--restart=always",
				"--security-opt", "no-new-privileges",
				"-v", "/var/run/docker.sock:/var/run/docker.sock",
				watchtowerImage,
				"--monitor-only", "--cleanup", "--interval", "86400",
			)
			if err == nil {
				c.Notes = append(c.Notes, "Watchtower ("+watchtowerImage+") checks for image updates daily (monitor-only — it never replaces containers)")
			}
			return err
		},
	}
}

// containerExists reports whether a container with the given name is present.
func containerExists(name string) bool {
	if system.DryRun {
		return false
	}
	out, err := system.Run("docker", "ps", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}")
	return err == nil && out != ""
}

// randomHex returns n random bytes hex-encoded (2n characters).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the platform is broken
	}
	return hex.EncodeToString(b)
}
