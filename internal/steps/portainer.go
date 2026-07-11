package steps

import "github.com/mxm-bbv/cli/internal/system"

func portainerStep() Step {
	return Step{
		Name: "Portainer Agent (port 9001)",
		Skip: func(c *Context) bool {
			return !c.Cfg.InstallPortainer || containerExists("portainer_agent")
		},
		Run: func(c *Context) error {
			// No "-v /:/host": that exposes the entire host filesystem to the
			// container. Basic agent operation doesn't need it. no-new-privileges
			// blocks setuid-based privilege escalation inside the container.
			_, err := system.Run("docker", "run", "-d",
				"-p", "9001:9001",
				"--name", "portainer_agent",
				"--restart=always",
				"--security-opt", "no-new-privileges",
				"-v", "/var/run/docker.sock:/var/run/docker.sock",
				"-v", "/var/lib/docker/volumes:/var/lib/docker/volumes",
				portainerAgentImage,
			)
			if err == nil {
				c.Notes = append(c.Notes, "Portainer Agent ("+portainerAgentImage+") on :9001 — connect it from your Portainer instance")
			}
			return err
		},
	}
}

func watchtowerStep() Step {
	return Step{
		Name: "Watchtower (auto-update containers)",
		Skip: func(c *Context) bool {
			return !c.Cfg.InstallWatchtower || containerExists("watchtower")
		},
		Run: func(c *Context) error {
			_, err := system.Run("docker", "run", "-d",
				"--name", "watchtower",
				"--restart=always",
				"--security-opt", "no-new-privileges",
				"-v", "/var/run/docker.sock:/var/run/docker.sock",
				watchtowerImage,
				"--cleanup", "--interval", "86400",
			)
			if err == nil {
				c.Notes = append(c.Notes, "Watchtower ("+watchtowerImage+") auto-updates containers daily")
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
