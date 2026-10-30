package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mxm-bbv/cli/internal/system"
)

// The test binary stands in for forge where a move's key runs it on the
// destination: `<binary> run move-receive …` (TestMoveLive).
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "run" {
		os.Exit(runModule(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func TestMovePath(t *testing.T) {
	root := "/var/lib/docker"
	for p, want := range map[string]string{
		"/srv/projects/votonia-prod": "folder",
		"/opt/app":                   "folder",
		"/home/deploy/apps/shop":     "folder",
		"/var/lib/docker/volumes/votonia_pg-data/_data":               "volume",
		"/var/lib/docker/volumes/caddy_data/_data/caddy/certificates": "volume",
	} {
		if kind, _, err := movePath(p, root); err != nil || kind != want {
			t.Errorf("%s: got %q, %v; want %s", p, kind, err, want)
		}
	}
	for _, p := range []string{
		"/", "/srv", "/etc/ssh", "/root/x", "/var/www/app", "/usr/local/bin", "/tmp/x/y", "/home/deploy",
		"/var/lib/docker/volumes/x", "/var/lib/docker/volumes/x/config", "/var/lib/docker/overlay2/abc",
		"/srv/projects/../etc", "/srv/projects/app/", "srv/projects/app", "/srv/projects/my app", "/srv/projects/$(id)",
	} {
		if kind, _, err := movePath(p, root); err == nil {
			t.Errorf("%s: allowed as %s", p, kind)
		}
	}
}

func TestMoveReceiveArgs(t *testing.T) {
	m := &moveManifest{ID: "m1", Paths: []string{"/srv/projects/app", "/var/lib/docker/volumes/app_db/_data"}}
	for _, cmd := range []string{
		"rsync --server -lHogDtpAXre.iLsfxCIvu --delete --numeric-ids . /srv/projects/app/",
		"rsync --server -lHogDtpre.iLsfxCIvu --numeric-ids . /var/lib/docker/volumes/app_db/_data",
		"rsync --server -lHogDtpAXre.iLsfxCIvu --delete --numeric-ids --usermap=1000:1001 --groupmap=1000:1001,4:5 . /srv/projects/app/",
	} {
		if args, err := moveReceiveArgs(cmd, m); err != nil || args[0] != "rsync" {
			t.Errorf("%q: %v", cmd, err)
		}
	}
	for cmd, want := range map[string]string{
		"sh -c id": "only rsync",
		"rsync --server --sender -lHogDtpre.iLsfxCIvu . /srv/projects/app/":               "nothing is read",
		"rsync --server -lHogDtpre.iLsfxCIvu --numeric-ids . /etc/":                       "isn't a path this move may write",
		"rsync --server -lHogDtpre.iLsfxCIvu --rsync-path=x . /srv/projects/app/":         "isn't allowed",
		"rsync --server -lHogDtpre.iLsfxCIvu --log-file=/etc/x . /srv/projects/app/":      "isn't allowed",
		"rsync --server -lHogDtpre.iLsfxCIvu /etc/passwd . /srv/projects/app/":            "isn't allowed",
		"rsync --server -lHogDtpre.iLsfxCIvu . /srv/projects/app/ /srv/projects/app/":     "after",
		"rsync --server -lHogDtpre.iLsfxCIvu --usermap=*:0 . /srv/projects/app/":          "isn't allowed",
		"rsync --server -lHogDtpre.iLsfxCIvu --groupmap=deploy:root . /srv/projects/app/": "isn't allowed",
		"rsync --server -lHogDtpre.iLsfxCIvu --usermap=1000:1001x . /srv/projects/app/":   "isn't allowed",
	} {
		if _, err := moveReceiveArgs(cmd, m); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", cmd, err, want)
		}
	}
}

// moveTempPaths lets a test use folders under the system's temp folder.
func moveTempPaths(t *testing.T) {
	t.Helper()
	saved := moveSystemPaths
	moveSystemPaths = slices.DeleteFunc(slices.Clone(saved), func(p string) bool { return strings.HasPrefix(os.TempDir(), p) })
	t.Cleanup(func() { moveSystemPaths = saved })
}

func TestAcceptPaths(t *testing.T) {
	moveTempPaths(t)
	base := t.TempDir()
	docker := filepath.Join(base, "docker")
	if err := os.MkdirAll(filepath.Join(docker, "volumes", "app_db", "_data"), 0o755); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(base, "projects", "full")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(base, "projects", "app")
	certs := filepath.Join(docker, "volumes", "app_db", "_data", "caddy", "certificates")
	if err := acceptPaths([]string{missing, certs}, nil, docker); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{missing, certs} {
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			t.Errorf("%s wasn't made", p)
		}
	}
	if err := acceptPaths([]string{full}, nil, docker); err == nil || !strings.Contains(err.Error(), "already holds files") {
		t.Errorf("a folder with files: %v", err)
	}
	if err := acceptPaths([]string{full}, []string{full}, docker); err != nil {
		t.Errorf("a folder this move filled before: %v", err)
	}
	if err := acceptPaths([]string{filepath.Join(docker, "volumes", "other", "_data")}, nil, docker); err == nil || !strings.Contains(err.Error(), "make it first") {
		t.Errorf("a volume that isn't there: %v", err)
	}
}

func TestRewriteAuthorizedKeys(t *testing.T) {
	home := t.TempDir()
	u := &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid()), HomeDir: home}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ssh-ed25519 AAAAmine me@laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	line := `restrict,from="100.64.0.1",command="sudo -n /usr/local/bin/forge run move-receive m1 \"$SSH_ORIGINAL_COMMAND\"" ssh-ed25519 AAAAmove forge-move:m1`
	for range 2 { // again: the line is replaced, not added twice
		if err := rewriteAuthorizedKeys(u, "m1", line); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	if string(data) != "ssh-ed25519 AAAAmine me@laptop\n"+line+"\n" {
		t.Fatalf("got:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	if err := rewriteAuthorizedKeys(u, "m1", ""); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "ssh-ed25519 AAAAmine me@laptop\n" {
		t.Fatalf("after close:\n%s", data)
	}
}

func TestMoveModulesRefuseBadInputs(t *testing.T) {
	for name, in := range map[string]map[string]string{
		"move-key":    {"move": "Bad ID"},
		"move-accept": {"move": "m1", "user": "root", "from": "100.64.0.1", "key": "ssh-ed25519 AAAA", "paths": "/srv/projects/app"},
		"move-send":   {"move": "m1", "to": "-oProxyCommand=x", "user": "deploy", "host_key": "ssh-ed25519 AAAA", "pairs": "/srv/projects/app /srv/projects/app"},
		"move-close":  {"move": "../x"},
	} {
		if _, _, err := findModule(name).build(in); err == nil {
			t.Errorf("%s took %v", name, in)
		}
	}
	accept := findModule("move-accept")
	for _, in := range []map[string]string{
		{"move": "m1", "user": "deploy", "from": "not-an-ip", "key": "ssh-ed25519 AAAA", "paths": "/srv/projects/app"},
		{"move": "m1", "user": "deploy", "from": "100.64.0.1", "key": "ssh-rsa AAAA", "paths": "/srv/projects/app"},
	} {
		if _, _, err := accept.build(in); err == nil {
			t.Errorf("move-accept took %v", in)
		}
	}
	send := findModule("move-send")
	for _, in := range []map[string]string{
		{"move": "m1", "to": "10.0.0.2", "user": "deploy", "host_key": "ssh-ed25519 AAAA", "images": "--output=/etc/x"},
		{"move": "m1", "to": "10.0.0.2", "user": "deploy", "host_key": "ssh-ed25519 AAAA", "images": "app:latest; rm -rf /"},
		{"move": "m1", "to": "10.0.0.2", "user": "deploy", "host_key": "ssh-ed25519 AAAA"},
		{"move": "m1", "to": "10.0.0.2", "user": "deploy", "host_key": "ssh-ed25519 AAAA", "pairs": "/srv/projects/app /srv/projects/app", "usermap": "*:0"},
	} {
		if _, _, err := send.build(in); err == nil {
			t.Errorf("move-send took %v", in)
		}
	}
	caddy := findModule("caddy")
	for _, p := range []string{"srv/projects", "/srv/../etc", "/", "/srv/projects;x"} {
		if _, _, err := caddy.build(map[string]string{"projects": p}); err == nil {
			t.Errorf("caddy took projects %q", p)
		}
	}
	if !findModule("move-send").Internal || !findModule("move-accept").Danger {
		t.Error("a move's modules are internal; letting a copy in is a danger")
	}
}

func TestMoveImageRefs(t *testing.T) {
	for ref, ok := range map[string]bool{
		"votonia-commerce":                         true,
		"centrifugo/centrifugo:v6":                 true,
		"timescale/timescaledb:2.29.0-pg18":        true,
		"ghcr.io/mr-studio-kz-ua/erp-api:sha-0d16": true,
		"localhost:5000/app:1":                     true,
		"sha256:" + strings.Repeat("a1", 32):       true,
		"-o":                                       false,
		"App:Latest":                               false,
		"app:latest extra":                         false,
		"sha256:abc":                               false,
	} {
		if moveImageRef(ref) != ok {
			t.Errorf("%q: want %v", ref, ok)
		}
	}
}

func TestRunPipe(t *testing.T) {
	system.DryRun = false
	out, sent, err := system.RunPipe("test", time.Minute, []string{"sh", "-c", "printf hello"}, []string{"sh", "-c", "wc -c; echo Loaded image: app:latest"})
	if err != nil || sent != 5 || !strings.Contains(out, "5") || !strings.Contains(out, "Loaded image") {
		t.Errorf("got %q %d %v", out, sent, err)
	}
	if _, _, err := system.RunPipe("test", time.Minute, []string{"sh", "-c", "printf hello; exit 3"}, []string{"cat"}); err == nil {
		t.Error("a failing save went through")
	}
	if _, _, err := system.RunPipe("test", time.Minute, []string{"sh", "-c", "head -c 10000000 /dev/zero"}, []string{"sh", "-c", "exit 4"}); err == nil {
		t.Error("a failing load went through")
	}
}

func TestRsyncStats(t *testing.T) {
	got := rsyncStats("Number of files: 1,234 (reg: 1,000, dir: 234)\nNumber of regular files transferred: 12\nTotal file size: 13,206,755,756 bytes\nTotal transferred file size: 5,000 bytes\n")
	if got["files"] != 1234 || got["transferred"] != 12 || got["bytes"] != 13206755756 || got["sent"] != 5000 {
		t.Errorf("got %v", got)
	}
}

// runMove runs a module the way `forge run` does and returns its done event.
func runMove(t *testing.T, name string, in map[string]string) map[string]any {
	t.Helper()
	m := findModule(name)
	st, ctx, err := m.build(in)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out bytes.Buffer
	code := machineRun(&out, m, in, st, ctx)
	var done map[string]any
	for _, line := range strings.Split(out.String(), "\n") {
		if body, ok := strings.CutPrefix(line, eventPrefix); ok && strings.Contains(body, `"event":"done"`) {
			_ = json.Unmarshal([]byte(body), &done)
		}
	}
	if code != 0 {
		t.Fatalf("%s failed: %s", name, out.String())
	}
	return done
}

// TestMoveLive copies a project folder and a volume through a real sshd,
// sudo and rsync, from and to this same machine: owners, links and hard links
// arrive as they were, a second pass removes what the source lost, and the
// key goes nowhere but into the paths it was given. Root in a throwaway
// container with sshd, sudo and rsync (deploy.me's sandbox image has them):
//
//	CGO_ENABLED=0 go test -c -o dist/forge.test .
//	docker run --rm -e FORGE_LIVE=1 -v $PWD/dist/forge.test:/forge.test:ro \
//	  --entrypoint /forge.test deployme-sshd-target:local -test.run MoveLive -test.v
func TestMoveLive(t *testing.T) {
	if os.Getenv("FORGE_LIVE") != "1" || os.Geteuid() != 0 || !system.FileExists("/.dockerenv") {
		t.Skip("set FORGE_LIVE=1 and run as root inside a disposable Docker container")
	}
	for _, bin := range []string{"sshd", "rsync", "sudo", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil && !system.FileExists("/usr/sbin/"+bin) {
			t.Skip(bin + " isn't installed")
		}
	}
	system.DryRun = false
	sh := func(script string) string {
		t.Helper()
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	exe, _ := os.Executable()
	sh(`id mover >/dev/null 2>&1 || useradd --create-home --shell /bin/bash mover; usermod -p "*" mover
		echo "mover ALL=(root) NOPASSWD: ` + exe + ` run *" > /etc/sudoers.d/forge-move-test && chmod 0440 /etc/sudoers.d/forge-move-test
		ssh-keygen -A >/dev/null; mkdir -p /run/sshd
		printf 'Port 2222\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPidFile /run/sshd-move-test.pid\n' > /etc/ssh/sshd_move_test
		/usr/sbin/sshd -f /etc/ssh/sshd_move_test`)

	// The source: a project folder and a volume, as containers leave them.
	sh(`mkdir -p /srv/projects/src-app/storage /var/lib/docker/volumes/app_db/_data /var/lib/docker/volumes/app_db2/_data
		echo code > /srv/projects/src-app/index.php
		echo upload > /srv/projects/src-app/storage/a.jpg && chown 33:33 /srv/projects/src-app/storage/a.jpg
		ln -sf storage /srv/projects/src-app/public
		ln -f /srv/projects/src-app/index.php /srv/projects/src-app/index-hard.php
		echo old > /srv/projects/src-app/gone.txt
		echo mine > /srv/projects/src-app/deploy.txt && chown 4242:4242 /srv/projects/src-app/deploy.txt /srv/projects/src-app
		echo pgdata > /var/lib/docker/volumes/app_db/_data/PG_VERSION && chown -R 70:70 /var/lib/docker/volumes/app_db/_data && chmod 0700 /var/lib/docker/volumes/app_db/_data`)

	key := runMove(t, "move-key", map[string]string{"move": "m1"})["result"].(map[string]any)["key"].(string)
	runMove(t, "move-accept", map[string]string{"move": "m1", "user": "mover", "from": "127.0.0.1", "key": key,
		"paths": "/srv/projects/dst-app\n/var/lib/docker/volumes/app_db2/_data"})
	hostKey := strings.Join(strings.Fields(sh("cat /etc/ssh/ssh_host_ed25519_key.pub"))[:2], " ")
	send := map[string]string{"move": "m1", "to": "127.0.0.1", "port": "2222", "user": "mover", "host_key": hostKey,
		"pairs": "/srv/projects/src-app /srv/projects/dst-app\n/var/lib/docker/volumes/app_db/_data /var/lib/docker/volumes/app_db2/_data", "delete": "no",
		"usermap": "4242:4343", "groupmap": "4242:4343"}
	done := runMove(t, "move-send", send)
	if done["result"].(map[string]any)["/srv/projects/src-app"] == nil {
		t.Errorf("no stats: %v", done)
	}

	check := func(script, want string) {
		t.Helper()
		if got := sh(script); got != want {
			t.Errorf("%s: got %q, want %q", script, got, want)
		}
	}
	check("stat -c %u:%g /srv/projects/dst-app/storage/a.jpg", "33:33")
	// The deploy user's files and the folder itself are the deploy user's there, whatever its ID.
	check("stat -c %u:%g /srv/projects/dst-app /srv/projects/dst-app/deploy.txt", "4343:4343\n4343:4343")
	check("readlink /srv/projects/dst-app/public", "storage")
	check("stat -c %h /srv/projects/dst-app/index.php", "2")
	check("stat -c '%u:%g %a' /var/lib/docker/volumes/app_db2/_data /var/lib/docker/volumes/app_db2/_data/PG_VERSION", "70:70 700\n70:70 644")
	check("cat /srv/projects/dst-app/gone.txt", "old")

	// An edge's certificates: only the moving project's hosts.
	sh(`mkdir -p /var/lib/docker/volumes/edge/_data/caddy/certificates/acme-v02/shop.kz /var/lib/docker/volumes/edge/_data/caddy/certificates/acme-v02/other.kz /var/lib/docker/volumes/edge2/_data
		echo cert > /var/lib/docker/volumes/edge/_data/caddy/certificates/acme-v02/shop.kz/shop.kz.crt
		echo cert > /var/lib/docker/volumes/edge/_data/caddy/certificates/acme-v02/other.kz/other.kz.crt`)
	runMove(t, "move-accept", map[string]string{"move": "m1", "user": "mover", "from": "127.0.0.1", "key": key,
		"paths": "/var/lib/docker/volumes/edge2/_data/caddy/certificates"})
	runMove(t, "move-send", map[string]string{"move": "m1", "to": "127.0.0.1", "port": "2222", "user": "mover", "host_key": hostKey,
		"pairs": "/var/lib/docker/volumes/edge/_data/caddy/certificates /var/lib/docker/volumes/edge2/_data/caddy/certificates", "only": "shop.kz"})
	check("cd /var/lib/docker/volumes/edge2/_data/caddy/certificates && find . -type f | sort", "./acme-v02/shop.kz/shop.kz.crt")

	// The second pass: what the source lost goes.
	sh("rm /srv/projects/src-app/gone.txt")
	send["delete"] = "yes"
	runMove(t, "move-send", send)
	check("test -e /srv/projects/dst-app/gone.txt && echo kept || echo gone", "gone")

	// The images: docker save on the source straight into docker load here, only
	// once move-accept allowed them. A docker of the test's own stands in.
	sh(`printf '%s\n' '#!/bin/sh' 'case "$1" in' 'info) echo /var/lib/docker ;;' 'save) shift; printf "%s\n" "$@"; head -c 3000000 /dev/zero ;;' 'load) cat > /tmp/move-loaded; echo "Loaded image: app:latest" ;;' 'esac' > /usr/local/sbin/docker; chmod 0755 /usr/local/sbin/docker`)
	ssh := "ssh -i /var/lib/forge/moves/m1/key -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mover@127.0.0.1 "
	if out, err := exec.Command("bash", "-c", ssh+"'docker load' </dev/null").CombinedOutput(); err == nil || !strings.Contains(string(out), "doesn't take images") {
		t.Errorf("docker load before images were allowed: %v\n%s", err, out)
	}
	runMove(t, "move-accept", map[string]string{"move": "m1", "user": "mover", "from": "127.0.0.1", "key": key, "paths": "/srv/projects/dst-app", "images": "yes"})
	done = runMove(t, "move-send", map[string]string{"move": "m1", "to": "127.0.0.1", "port": "2222", "user": "mover", "host_key": hostKey, "images": "app:latest\nredis:7-alpine"})
	images, _ := done["result"].(map[string]any)["images"].(map[string]any)
	if images == nil || images["loaded"] != float64(1) && images["loaded"] != 1 {
		t.Errorf("images: %v", done)
	}
	check("head -n 2 /tmp/move-loaded", "app:latest\nredis:7-alpine")
	check("stat -c %s /tmp/move-loaded", "3000026")

	// The key reaches nothing but the receiving rsync into those paths, and docker load.
	for _, cmd := range []string{"id", "'rsync --server -lHogDtpre.iLsfxCIvu . /etc/'", "'rsync --server --sender -lHogDtpre.iLsfxCIvu . /srv/projects/dst-app/'"} {
		out, err := exec.Command("bash", "-c", ssh+cmd).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "forge move-receive") {
			t.Errorf("%s: %v\n%s", cmd, err, out)
		}
	}
	if err := exec.Command("bash", "-c", "rsync -a -e 'ssh -i /var/lib/forge/moves/m1/key -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' /srv/projects/src-app/ mover@127.0.0.1:/srv/projects/other/").Run(); err == nil {
		t.Error("rsync into a path the move wasn't given went through")
	}

	runMove(t, "move-close", map[string]string{"move": "m1", "forget": "yes"})
	check("grep -c forge-move ~mover/.ssh/authorized_keys || true", "0")
	for _, p := range []string{"/var/lib/forge/moves/m1", "/var/lib/forge/moves/m1.json"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
}
