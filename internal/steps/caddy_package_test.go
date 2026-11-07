package steps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

type packed struct {
	name string
	kind byte
	body string
	link string
}

func caddyTar(t *testing.T, entries ...packed) string {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	w := tar.NewWriter(gz)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: kind, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if kind != tar.TypeReg {
			h.Size = 0
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.Close()
	gz.Close()
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

var goodCompose = packed{name: "docker-compose.prod.yml", body: "services: {}\n"}

// TestCaddyPackageOpens: a whole setup comes through, folders and all.
func TestCaddyPackageOpens(t *testing.T) {
	files, err := readCaddyPackage(caddyTar(t,
		packed{name: "./", kind: tar.TypeDir},
		goodCompose,
		packed{name: "core/prod/caddy/", kind: tar.TypeDir},
		packed{name: "./core/prod/caddy/Caddyfile", body: "{ email me@example.com }\n"},
		packed{name: "examples/laravel.caddy.example", body: "# a template\n"},
	))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, f := range files {
		names = append(names, f.name)
	}
	if strings.Join(names, " ") != "docker-compose.prod.yml core/prod/caddy/Caddyfile examples/laravel.caddy.example" {
		t.Errorf("files: %v", names)
	}
}

// TestCaddyPackageRefusesWhatIsntASetup: what's unpacked runs in Docker, as a
// user that may as well be root: nothing but plain files, inside its own folder.
func TestCaddyPackageRefusesWhatIsntASetup(t *testing.T) {
	big := strings.Repeat("x", caddyPackageMax+1)
	for name, c := range map[string]struct{ data, want string }{
		"not base64":    {"%%%", "isn't base64"},
		"not gzip":      {base64.StdEncoding.EncodeToString([]byte("plain")), "isn't a .tar.gz"},
		"no compose":    {caddyTar(t, packed{name: "README.md", body: "hi"}), "no docker-compose.prod.yml"},
		"climbs out":    {caddyTar(t, goodCompose, packed{name: "../../.ssh/authorized_keys", body: "key"}), "outside itself"},
		"climbs inside": {caddyTar(t, goodCompose, packed{name: "a/../../b", body: "x"}), "outside itself"},
		"absolute":      {caddyTar(t, goodCompose, packed{name: "/etc/cron.d/x", body: "x"}), "outside itself"},
		"a symlink":     {caddyTar(t, goodCompose, packed{name: "link", kind: tar.TypeSymlink, link: "/etc/passwd"}), "other than files and folders"},
		"a hard link":   {caddyTar(t, goodCompose, packed{name: "link", kind: tar.TypeLink, link: "/etc/passwd"}), "other than files and folders"},
		"a device":      {caddyTar(t, goodCompose, packed{name: "dev", kind: tar.TypeChar}), "other than files and folders"},
		"too big":       {caddyTar(t, goodCompose, packed{name: "huge", body: big}), "too big"},
	} {
		if _, err := readCaddyPackage(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// TestCaddyPackageNeedsNoGitHub: it goes to ~/caddy-server, clones nothing, needs
// no key, and comes up with the compose file it brought.
func TestCaddyPackageNeedsNoGitHub(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	cfg := config.Default()
	cfg.Username, cfg.CaddyRepo = "deploy", config.CaddyPackage
	cfg.CaddyPackageData = caddyTar(t, goodCompose, packed{name: "core/prod/caddy/Caddyfile", body: "{}\n"})
	if cfg.CaddyFromRepo() || cfg.Validate() != nil {
		t.Fatalf("a package isn't a repo: %v", cfg.Validate())
	}
	c := &Context{Cfg: cfg}
	if !githubStep().Skip(c) {
		t.Error("the GitHub step runs for a package")
	}
	if err := caddyStep().Run(c); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(system.CommandLog, "\n")
	for _, want := range []string{
		"write /home/deploy/caddy-server/docker-compose.prod.yml",
		"write /home/deploy/caddy-server/core/prod/caddy/Caddyfile",
		"write /home/deploy/caddy-server/.env",
		"/home/deploy/caddy-server/docker-compose.prod.yml up -d --remove-orphans",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q:\n%s", want, log)
		}
	}
	for _, not := range []string{"git ", "gh ", "github"} {
		if strings.Contains(log, not) {
			t.Errorf("it reached for %q:\n%s", not, log)
		}
	}
}

// TestCaddyPackageAgainKeepsTheServersOwn: a package coming again brings its files
// and leaves the server's .env and site files, and a run with none sent stays put.
func TestCaddyPackageAgainKeepsTheServersOwn(t *testing.T) {
	dryRunAs(t, ubuntuNoble, false)
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/"+caddyPackageSites, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".env", caddyPackageSites + "shop.caddy"} {
		if err := os.WriteFile(dir+"/"+f, []byte("the server's\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data := caddyTar(t, goodCompose,
		packed{name: ".env", body: "PROJECTS_PATH=/elsewhere\n"},
		packed{name: caddyPackageSites + "shop.caddy", body: "packaged\n"},
		packed{name: caddyPackageSites + "new.caddy", body: "packaged\n"},
	)
	if err := installCaddyPackage("deploy", dir, data); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(system.CommandLog, "\n")
	for _, kept := range []string{"write " + dir + "/.env", "write " + dir + "/" + caddyPackageSites + "shop.caddy"} {
		if strings.Contains(log, kept) {
			t.Errorf("written over: %s\n%s", kept, log)
		}
	}
	for _, want := range []string{"write " + dir + "/docker-compose.prod.yml", "write " + dir + "/" + caddyPackageSites + "new.caddy"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %s:\n%s", want, log)
		}
	}

	system.CommandLog = nil
	if err := installCaddyPackage("deploy", dir, ""); err != nil {
		t.Fatal(err)
	}
	if len(system.CommandLog) != 0 {
		t.Errorf("with none sent, nothing changes: %v", system.CommandLog)
	}
}
