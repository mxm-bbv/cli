package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mxm-bbv/cli/internal/ui"
)

// runRotateAgents is the red button for a lost or leaked AGENT_SECRET, run
// on the machine with the Portainer Server: a new secret goes to every
// server's agent (over SSH, via stdin — never on a command line), then into
// the Portainer Server's .env, which is restarted with it.
//
// Agents are rotated first: until the server restarts they keep running, so
// a server that can't be reached is reported, not lost.
func runRotateAgents(args []string) int {
	conf, err := loadRotateConf()
	if err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		return 1
	}
	var hosts []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--portainer" && i+1 < len(args):
			conf.portainer = args[i+1]
			i++
		case strings.HasPrefix(args[i], "-"):
			ui.Println(ui.StyleErr.Render("  unknown option " + args[i] + "\n  usage: forge rotate-agents [--portainer DIR] [user@host …]"))
			return 2
		default:
			hosts = append(hosts, args[i])
		}
	}
	if len(hosts) > 0 {
		conf.hosts = hosts
	}
	if len(conf.hosts) == 0 || conf.portainer == "" {
		ui.Println(ui.StyleErr.Render("  usage: forge rotate-agents --portainer DIR user@host [user@host …]") +
			ui.StyleMuted.Render("\n  DIR holds your Portainer Server's compose file; servers and DIR are remembered for next time."))
		return 2
	}
	compose, err := findCompose(conf.portainer)
	if err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		return 1
	}
	if err := conf.save(); err != nil {
		ui.Println(ui.StyleWarn.Render("  could not remember the servers: " + err.Error()))
	}

	ok, err := ui.Confirm(fmt.Sprintf("Rotate AGENT_SECRET on %d servers and your Portainer Server?", len(conf.hosts)),
		"Servers: "+strings.Join(conf.hosts, ", ")+"\nPortainer: "+compose+
			"\nEvery agent gets a new secret, then Portainer restarts with it. Running containers are not touched.")
	if err != nil || !ok {
		ui.Println(ui.StyleMuted.Render("  Nothing changed."))
		return 0
	}
	pw, err := ui.AskSecret("sudo password on the servers (blank if sudo needs none)")
	if err != nil {
		return 1
	}

	secret := newSecret()
	var done, failed []string
	for _, h := range conf.hosts {
		ui.Println(ui.StyleKey.Render("  → " + h))
		out, err := rotateOn(h, pw, secret)
		if err != nil {
			failed = append(failed, h)
			ui.Println(ui.StyleErr.Render("    ✗ "+err.Error()) + "\n" + indent(lastLines(out, 6), "      "))
			continue
		}
		done = append(done, h)
		ui.Println(ui.StyleOK.Render("    ✓ agent recreated with the new secret"))
	}

	if len(done) == 0 {
		ui.Println(ui.StyleErr.Render("\n  No server took the new secret — Portainer left as it was."))
		return 1
	}
	if err := switchPortainer(conf.portainer, compose, secret); err != nil {
		ui.Println(ui.StyleErr.Render("\n  Agents rotated, but Portainer wasn't switched: "+err.Error()) +
			ui.StyleMuted.Render("\n  The new secret is in "+filepath.Join(conf.portainer, ".env")))
		return 1
	}
	ui.Println(ui.StyleOK.Render(fmt.Sprintf("\n  Done: %d servers and Portainer use the new AGENT_SECRET", len(done))) +
		ui.StyleMuted.Render(" (kept in "+filepath.Join(conf.portainer, ".env")+")"))
	if len(failed) > 0 {
		ui.Println(ui.StyleWarn.Render("  Not rotated: "+strings.Join(failed, ", ")) +
			ui.StyleMuted.Render("\n  They show as Down. On each:  sudo forge agent-secret  and paste the secret from .env"))
		return 1
	}
	return 0
}

// rotateOn updates forge on host and recreates its agent with secret. The
// sudo password and the secret travel on stdin: sudo -S takes the first
// line, `forge agent-secret --stdin` the second.
func rotateOn(host, sudoPw, secret string) (string, error) {
	sudo := "sudo -S -p ''"
	input := sudoPw + "\n" + secret + "\n"
	if sudoPw == "" {
		sudo, input = "sudo -n", secret+"\n"
	}
	remote := sudo + ` sh -c 'command -v forge >/dev/null || { echo "forge is not installed here"; exit 3; }; ` +
		`forge update </dev/null >/dev/null 2>&1; exec forge agent-secret --stdin'`
	cmd := exec.Command("ssh", "-T", "-o", "ConnectTimeout=15", host, remote)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("failed (%v)", err)
	}
	return string(out), nil
}

// switchPortainer stores secret in DIR/.env and restarts the Portainer
// Server with it, enabling the AGENT_SECRET line forge wrote commented out.
func switchPortainer(dir, compose, secret string) error {
	data, err := os.ReadFile(compose)
	if err != nil {
		return err
	}
	text := strings.Replace(string(data),
		"    # environment:\n    #   - AGENT_SECRET=", "    environment:\n      - AGENT_SECRET=", 1)
	if !strings.Contains(text, "AGENT_SECRET=${AGENT_SECRET") {
		return fmt.Errorf("%s doesn't pass AGENT_SECRET to Portainer — add  environment: [AGENT_SECRET=${AGENT_SECRET}]  to its service", compose)
	}
	if text != string(data) {
		if err := os.WriteFile(compose, []byte(text), 0o644); err != nil {
			return err
		}
	}
	if err := setEnvVar(filepath.Join(dir, ".env"), "AGENT_SECRET", secret); err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "-f", compose, "up", "-d")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker compose up: %v\n%s", err, lastLines(string(out), 6))
	}
	return nil
}

// setEnvVar sets key=value in an env file (root-only permissions), keeping
// its other lines.
func setEnvVar(path, key, value string) error {
	data, _ := os.ReadFile(path)
	var lines []string
	found := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if strings.HasPrefix(l, key+"=") {
			l, found = key+"="+value, true
		}
		if l != "" {
			lines = append(lines, l)
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func findCompose(dir string) (string, error) {
	for _, n := range []string{"docker-compose.local.yml", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if p := filepath.Join(dir, n); fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no compose file for Portainer in %s", dir)
}

func newSecret() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// rotateConf is ~/.config/forge/agents.conf: the Portainer directory and
// the servers whose agents it manages.
type rotateConf struct {
	path      string
	portainer string
	hosts     []string
}

func loadRotateConf() (rotateConf, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return rotateConf{}, err
	}
	c := rotateConf{path: filepath.Join(dir, "forge", "agents.conf")}
	f, err := os.Open(c.path)
	if err != nil {
		return c, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		switch k {
		case "portainer":
			c.portainer = v
		case "host":
			c.hosts = append(c.hosts, v)
		}
	}
	return c, nil
}

func (c rotateConf) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# forge rotate-agents: Portainer Server directory and agent servers\nportainer=" + c.portainer + "\n")
	for _, h := range c.hosts {
		b.WriteString("host=" + h + "\n")
	}
	return os.WriteFile(c.path, []byte(b.String()), 0o600)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func indent(s, pre string) string {
	if s == "" {
		return ""
	}
	return pre + strings.ReplaceAll(s, "\n", "\n"+pre)
}
