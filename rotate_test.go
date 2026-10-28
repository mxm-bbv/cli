package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotateOnKeepsSecretsOffTheCommandLine: the sudo password and the new
// secret reach the server on stdin, never in ssh's arguments (visible in ps
// and shell history on both ends).
func TestRotateOnKeepsSecretsOffTheCommandLine(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "ssh.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + log + ".args\ncat > " + log + ".stdin\necho ok\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	if _, err := rotateOn("deploy@100.64.0.7", "sudo-pw", "new-secret-value"); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log + ".args")
	stdin, _ := os.ReadFile(log + ".stdin")
	if strings.Contains(string(args), "new-secret-value") || strings.Contains(string(args), "sudo-pw") {
		t.Errorf("secrets on the command line:\n%s", args)
	}
	if string(stdin) != "sudo-pw\nnew-secret-value\n" {
		t.Errorf("stdin = %q", stdin)
	}
	if !strings.Contains(string(args), "forge agent-secret --stdin") || !strings.Contains(string(args), "sudo -S") {
		t.Errorf("remote command: %s", args)
	}
}

func TestSwitchPortainerEnablesSecret(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.local.yml")
	_ = os.WriteFile(compose, []byte("services:\n  core:\n    image: portainer/portainer-ce:lts\n"+
		"    # environment:\n    #   - AGENT_SECRET=${AGENT_SECRET:?set AGENT_SECRET in .env}\n    restart: always\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OTHER=1\nAGENT_SECRET=old\n"), 0o600)
	t.Setenv("PATH", t.TempDir()) // no docker: stop right after the files are written

	_ = switchPortainer(dir, compose, "fresh")
	got, _ := os.ReadFile(compose)
	if !strings.Contains(string(got), "    environment:\n      - AGENT_SECRET=${AGENT_SECRET") {
		t.Errorf("AGENT_SECRET line not enabled:\n%s", got)
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(env) != "OTHER=1\nAGENT_SECRET=fresh\n" {
		t.Errorf(".env = %q", env)
	}
	if fi, _ := os.Stat(filepath.Join(dir, ".env")); fi.Mode().Perm() != 0o600 {
		t.Errorf(".env mode %v", fi.Mode().Perm())
	}
}

func TestRotateConfRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c, _ := loadRotateConf()
	c.portainer, c.hosts = "/srv/portainer", []string{"deploy@100.1.2.3", "root@100.4.5.6"}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	got, _ := loadRotateConf()
	if got.portainer != c.portainer || strings.Join(got.hosts, " ") != strings.Join(c.hosts, " ") {
		t.Errorf("got %+v", got)
	}
}
