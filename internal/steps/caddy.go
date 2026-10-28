package steps

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// caddyNetwork is the external Docker network the caddy-core compose file
// expects; app containers join it so Caddy can reach them by name.
const caddyNetwork = "proxy-network"

// caddyStep installs the operator's own Caddy setup — a git repo with a
// docker-compose.prod.yml (caddy-core) — as the box's web server on :80/:443.
// A private repo is cloned with its read-only deploy key (githubStep runs
// first and covers it). Re-running pulls the repo and re-ups the stack.
func caddyStep() Step {
	return Step{
		Name: "Caddy web server (your caddy repo)",
		Skip: func(c *Context) bool { return c.Cfg.CaddyRepo == "" },
		Run: func(c *Context) error {
			cfg := c.Cfg
			user := cfg.Username
			dir := caddyDir(cfg.HomeDir(), cfg.CaddyRepo)
			compose := dir + "/docker-compose.prod.yml"

			if !system.FileExists(dir + "/.git") {
				if _, err := system.Run("runuser", "-u", user, "--", "git", "clone", "--quiet", caddyCloneURL(cfg.CaddyRepo), dir); err != nil {
					return fmt.Errorf("clone %s: %w", cfg.CaddyRepo, err)
				}
			} else if _, err := system.Run("runuser", "-u", user, "--", "git", "-C", dir, "pull", "--ff-only", "--quiet"); err != nil {
				c.Notes = append(c.Notes, "⚠ "+dir+" has local changes — not updated from git; the stack runs as it is")
			}
			if !system.DryRun && !system.FileExists(compose) {
				return fmt.Errorf("%s has no docker-compose.prod.yml — is it the caddy repo?", cfg.CaddyRepo)
			}

			// PROJECTS_PATH is mounted into Caddy as /projects (static files,
			// PHP roots); a deploy box keeps projects in the deploy user's home.
			projects := cfg.HomeDir() + "/projects"
			if _, err := system.Run("install", "-d", "-o", user, "-g", user, projects); err != nil {
				return err
			}
			if !system.FileExists(dir + "/.env") {
				if err := system.WriteFile(dir+"/.env", "PROJECTS_PATH="+projects+"\n", 0o644); err != nil {
					return err
				}
				if _, err := system.Run("chown", user+":"+user, dir+"/.env"); err != nil {
					return err
				}
			}

			if _, err := system.Output("docker", "network", "inspect", caddyNetwork); err != nil {
				if _, err := system.Run("docker", "network", "create", caddyNetwork); err != nil {
					return err
				}
			}
			up := []string{"-u", user, "--", "docker", "compose", "--project-directory", dir, "-f", compose}
			if _, err := system.Run("runuser", append(up, "up", "-d", "--remove-orphans")...); err != nil {
				return err
			}
			if _, err := system.Run("runuser", append(up, "exec", "-T", "caddy", "caddy", "validate", "--config", "/etc/caddy/Caddyfile")...); err != nil {
				c.Notes = append(c.Notes, "⚠ Caddy is up but `caddy validate` failed — check its config in "+dir)
			}

			sites := dir + "/core/prod/caddy/configs"
			c.Notes = append(c.Notes, fmt.Sprintf("Caddy serves :80/:443 from %s. A new site: a *.caddy file in %s (templates in %s/examples), then  docker exec main-server caddy reload --config /etc/caddy/Caddyfile. App containers join the %q network.",
				dir, sites, dir, caddyNetwork))
			return nil
		},
	}
}

// caddyDir is where the repo is checked out: ~/<repo name>.
func caddyDir(home, repo string) string {
	return home + "/" + repo[strings.LastIndex(repo, "/")+1:]
}

// caddyCloneURL: anonymous HTTPS for a public repo, otherwise the SSH URL,
// which the deploy user's git routes through the repo's deploy key.
func caddyCloneURL(repo string) string {
	if repoIsPublic(repo) {
		return "https://github.com/" + repo + ".git"
	}
	return "git@github.com:" + repo + ".git"
}

// repoIsPublic asks GitHub anonymously; a private repo answers 401 and git,
// unable to prompt, fails. A variable so tests decide.
var repoIsPublic = func(repo string) bool {
	if system.DryRun {
		return false
	}
	cmd := exec.Command("git", "ls-remote", "--heads", "https://github.com/"+repo+".git")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/true")
	return cmd.Run() == nil
}
