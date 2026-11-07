package steps

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// caddyNetwork is the external Docker network the Caddy compose file expects;
// app containers join it so Caddy can reach them by name.
const caddyNetwork = "proxy-network"

// caddyStep puts the box's web server on :80/:443: a whole setup a program sent
// as a package, forge's own from the official image (either way nothing to clone,
// no repo access, no keys), or the operator's own git repo with a
// docker-compose.prod.yml, a private one cloned with its read-only deploy key
// (githubStep runs first and covers it). Re-running unpacks the package again,
// moves forge's own to the image this forge pins, or pulls the repo, and re-ups the stack.
func caddyStep() Step {
	return Step{
		Name: "Caddy web server",
		Skip: func(c *Context) bool { return c.Cfg.CaddyRepo == "" },
		Run: func(c *Context) error {
			cfg := c.Cfg
			user := cfg.Username
			dir := caddyDir(cfg.HomeDir(), cfg.CaddyRepo)
			compose := dir + "/docker-compose.prod.yml"

			switch {
			case cfg.CaddyFromRepo():
				if err := checkoutCaddy(c, dir); err != nil {
					return err
				}
			case cfg.CaddyRepo == config.CaddyPackage:
				if err := installCaddyPackage(user, dir, cfg.CaddyPackageData); err != nil {
					return err
				}
			default:
				if err := writeBuiltinCaddy(user, dir); err != nil {
					return err
				}
			}
			if !system.DryRun && !system.FileExists(compose) {
				return fmt.Errorf("%s has no docker-compose.prod.yml — is it a Caddy setup?", dir)
			}

			// PROJECTS_PATH is mounted into Caddy as /projects (static files,
			// PHP roots); a deploy box keeps projects in the deploy user's home
			// unless the setup names another folder (/srv/projects).
			projects := cfg.HomeDir() + "/projects"
			if cfg.CaddyProjects != "" {
				projects = cfg.CaddyProjects
			}
			if _, err := system.Run("install", "-d", "-o", user, "-g", user, projects); err != nil {
				return err
			}
			if system.FileExists(dir+"/.env") && cfg.CaddyProjects != "" && !system.FileContains(dir+"/.env", "PROJECTS_PATH="+projects) {
				c.Notes = append(c.Notes, "⚠ "+dir+"/.env names another PROJECTS_PATH, and it stays: the sites already there read their files through it")
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
			c.Notes = append(c.Notes, fmt.Sprintf("Caddy serves :80/:443 from %s. A new site: a *.caddy file in %s, then  docker exec main-server caddy reload --config /etc/caddy/Caddyfile. App containers join the %q network.",
				dir, sites, caddyNetwork))
			return nil
		},
	}
}

// checkoutCaddy puts the caddy repo at dir: a fresh clone, a pull of an
// existing one, or — when GitHub can't be reached or refuses the key — the
// built-in copy of the same layout, so the box serves :80/:443 regardless.
// A built-in copy is replaced by the real clone on the next run (`forge
// caddy`), keeping the site configs added to it meanwhile.
func checkoutCaddy(c *Context, dir string) error {
	cfg := c.Cfg
	user := cfg.Username
	builtin := system.FileExists(dir + "/" + caddyBuiltinMarker)
	switch {
	case system.FileExists(dir + "/.git"):
		if _, err := system.Run("runuser", "-u", user, "--", "git", "-C", dir, "pull", "--ff-only", "--quiet"); err != nil {
			c.Notes = append(c.Notes, "⚠ "+dir+" has local changes or GitHub is unreachable — not updated; the stack runs as it is")
		}
		return nil
	case system.FileExists(dir) && !builtin:
		return fmt.Errorf("%s exists but is not a git checkout of %s — move it away first", dir, cfg.CaddyRepo)
	}

	clone := dir
	if builtin {
		clone = dir + ".clone"
		_ = system.RemoveAll(clone)
	}
	if _, err := system.Run("runuser", "-u", user, "--", "git", "clone", "--quiet", caddyCloneURL(cfg.CaddyRepo), clone); err != nil {
		if builtin {
			c.Notes = append(c.Notes, "⚠ GitHub still unreachable for "+cfg.CaddyRepo+" — Caddy keeps running from the built-in setup")
			return nil
		}
		c.Notes = append(c.Notes, "⚠ couldn't clone "+cfg.CaddyRepo+" (GitHub unreachable or the deploy key missing) — Caddy runs from forge's built-in copy of the same layout. Switch later:  sudo forge caddy")
		return writeBuiltinCaddy(user, dir)
	}
	if builtin {
		// Keep the sites added to the built-in copy, then swap it out.
		_, _ = system.RunShell(fmt.Sprintf("cp -n %s/core/prod/caddy/configs/*.caddy %s/core/prod/caddy/configs/ 2>/dev/null; cp -n %s/.env %s/ 2>/dev/null; true", dir, clone, dir, clone))
		_ = system.RemoveAll(dir + ".builtin-old")
		if _, err := system.Run("mv", dir, dir+".builtin-old"); err != nil {
			return err
		}
		if _, err := system.Run("mv", clone, dir); err != nil {
			return err
		}
		c.Notes = append(c.Notes, "Caddy switched from the built-in setup to "+cfg.CaddyRepo+" (old copy: "+dir+".builtin-old)")
	}
	return nil
}

// caddyBuiltinMarker marks forge's built-in copy of the caddy layout.
const caddyBuiltinMarker = ".forge-builtin"

// caddyBuiltinKept are the built-in files a re-run leaves as they are: the
// operator may have added to them. The compose file is forge's, and carries the pin.
var caddyBuiltinKept = map[string]bool{"core/prod/caddy/Caddyfile": true}

// The built-in setup has the layout a repo of the operator's would (caddy-core's
// prod one): same container name, network, mounts and configs/*.caddy import.
var builtinCaddyFiles = map[string]string{
	caddyBuiltinMarker: "forge's own Caddy setup: `sudo forge caddy` moves it to the image this forge pins\n",
	"docker-compose.prod.yml": `networks:
  proxy-network:
    external: true

volumes:
  caddy-config:
  caddy-data:

services:
  caddy:
    image: ` + caddyImage + `
    container_name: main-server
    restart: always
    ports:
      - "80:80"
      - "443:443"
    environment:
      - CADDYPATH=/data
    volumes:
      - ./core/prod/caddy:/etc/caddy:ro
      - caddy-data:/data:rw
      - caddy-config:/config
      - ${PROJECTS_PATH}:/projects:ro
    networks:
      - proxy-network
`,
	"core/prod/caddy/Caddyfile": `{
    storage file_system {
        root /data
    }
}

import /etc/caddy/configs/*.caddy
`,
	"core/prod/caddy/configs/.gitkeep": "",
}

func writeBuiltinCaddy(user, dir string) error {
	for name, body := range builtinCaddyFiles {
		p := dir + "/" + name
		if _, err := system.Run("install", "-d", "-o", user, "-g", user, p[:strings.LastIndex(p, "/")]); err != nil {
			return err
		}
		if caddyBuiltinKept[name] && system.FileExists(p) {
			continue
		}
		if err := system.WriteFile(p, body, 0o644); err != nil {
			return err
		}
	}
	_, err := system.Run("chown", "-R", user+":"+user, dir)
	return err
}

// caddyDir is where its setup lives: ~/caddy-server for a package, ~/caddy for
// forge's own, else ~/<repo name>.
func caddyDir(home, repo string) string {
	switch repo {
	case config.CaddyPackage:
		return home + "/caddy-server"
	case config.CaddyBuiltin:
		return home + "/caddy"
	}
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
