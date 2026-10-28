package steps

import (
	"crypto/rand"
	"encoding/hex"
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
					// Not logged in to Tailscale yet: there is no address to
					// bind to, and 0.0.0.0 is not an option. `forge tailscale`
					// starts the agent right after login.
					// An agent from earlier (an older forge, by hand) may still
					// sit on a public port: never leave one behind.
					if containerExists("portainer_agent") {
						if hostIP, _ := inspectAgent(); !IsTailnetIP(hostIP) {
							if _, err := system.Run("docker", "rm", "-f", "portainer_agent"); err != nil {
								return err
							}
							c.Notes = append(c.Notes, "Removed a Portainer Agent that wasn't bound to Tailscale")
						}
					}
					c.AgentDeferred = true
					c.Notes = append(c.Notes, "Portainer Agent starts right after Tailscale login (sudo forge tailscale) — it binds to the tailnet IP only")
					return nil
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
			// port can pair with the agent.
			if c.AgentSecret == "" {
				c.AgentSecret = randomHex(16)
			}
			if err := runAgentContainer(publish, c.AgentSecret); err != nil {
				return err
			}
			where := "tailnet-only, invisible to the internet"
			if bindIP == "" {
				where = "PUBLIC — allowed through DOCKER-USER; consider tailnet mode instead"
			}
			c.Notes = append(c.Notes, "Portainer Agent ("+portainerAgentImage+") on "+bindIP+":9001 ("+where+")")
			return nil
		},
	}
}

// runAgentContainer starts the Portainer Agent with the given `-p` publish spec
// and AGENT_SECRET. The secret is passed via the environment (`-e AGENT_SECRET`
// with no value), so it never appears in the docker command line or the forge
// command log. No "-v /:/host": that would expose the whole host filesystem;
// the agent only needs the docker socket and volume dir. no-new-privileges
// blocks setuid-based escalation inside the container.
func runAgentContainer(publish, secret string) error {
	_, err := system.RunEnv([]string{"AGENT_SECRET=" + secret},
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
	return err
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
			return !c.Cfg.InstallWatchtower ||
				(containerExists("watchtower") && runningImage("watchtower") == watchtowerImage)
		},
		Run: func(c *Context) error {
			// An existing container on another image (e.g. the archived
			// containrrr/watchtower, which crash-loops on Docker 29+) is
			// replaced, not kept.
			if containerExists("watchtower") {
				if _, err := system.Run("docker", "rm", "-f", "watchtower"); err != nil {
					return err
				}
			}
			if err := runWatchtowerContainer(); err != nil {
				return err
			}
			c.Notes = append(c.Notes, "Watchtower ("+watchtowerImage+") checks for image updates daily (monitor-only — it never replaces containers)")
			return nil
		},
	}
}

// runWatchtowerContainer starts Watchtower in --monitor-only mode: it holds the
// docker socket, so letting it auto-replace containers with whatever a registry
// serves is a supply-chain risk. It only reports; you update deliberately.
func runWatchtowerContainer() error {
	_, err := system.Run("docker", "run", "-d",
		"--name", "watchtower",
		"--restart=always",
		"--security-opt", "no-new-privileges",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		watchtowerImage,
		"--monitor-only", "--cleanup", "--interval", "86400",
	)
	return err
}

// runningImage returns the image reference a named container was created from.
func runningImage(name string) string {
	if system.DryRun {
		return ""
	}
	out, err := system.Run("docker", "inspect", name, "--format", "{{.Config.Image}}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// UpdateImages re-pulls the pinned images and recreates the agent/watchtower
// containers when their running image drifts from the pin. It preserves the
// agent's bind IP and AGENT_SECRET. Returns the list of human-readable actions
// taken (empty when everything was already current).
func UpdateImages() ([]string, error) {
	var done []string

	if containerExists("portainer_agent") && runningImage("portainer_agent") != portainerAgentImage {
		bindIP, secret := inspectAgent()
		publish := "9001:9001"
		if bindIP != "" {
			publish = bindIP + ":9001:9001"
		}
		if secret == "" {
			secret = randomHex(16)
		}
		if _, err := system.Run("docker", "pull", portainerAgentImage); err != nil {
			return done, err
		}
		if _, err := system.Run("docker", "rm", "-f", "portainer_agent"); err != nil {
			return done, err
		}
		if err := runAgentContainer(publish, secret); err != nil {
			return done, err
		}
		done = append(done, "portainer_agent -> "+portainerAgentImage+" (binding and secret preserved)")
	}

	if containerExists("watchtower") && runningImage("watchtower") != watchtowerImage {
		if _, err := system.Run("docker", "pull", watchtowerImage); err != nil {
			return done, err
		}
		if _, err := system.Run("docker", "rm", "-f", "watchtower"); err != nil {
			return done, err
		}
		if err := runWatchtowerContainer(); err != nil {
			return done, err
		}
		done = append(done, "watchtower -> "+watchtowerImage)
	}
	return done, nil
}

// PinnedImages returns the images forge pins, for `forge status`/`update`.
func PinnedImages() (agent, watchtower string) {
	return portainerAgentImage, watchtowerImage
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
