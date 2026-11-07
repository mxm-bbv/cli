package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

// TestModulesCatalog: every module a program can list is one it can run,
// and its questions are of the kinds it knows how to ask.
func TestModulesCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range modules {
		if seen[m.Name] || findModule(m.Name) == nil || m.build == nil || m.Title == "" || m.Description == "" {
			t.Errorf("module %q: duplicate, unfindable or incomplete", m.Name)
		}
		seen[m.Name] = true
		for _, q := range m.Inputs {
			if !slices.Contains([]string{"text", "secret", "choice"}, q.Type) {
				t.Errorf("%s.%s: unknown type %q", m.Name, q.Name, q.Type)
			}
			if (q.Type == "choice") != (len(q.Options) > 0) {
				t.Errorf("%s.%s: a choice and only a choice has options", m.Name, q.Name)
			}
		}
	}
	for _, name := range []string{"setup", "ssh-login", "tailscale", "agent-secret", "agent-remove", "github", "caddy", "ssh", "tripwire-baseline", "alerts", "update", "auto-update"} {
		if !seen[name] {
			t.Errorf("module %s missing", name)
		}
	}
}

func TestReadInputs(t *testing.T) {
	ssh := findModule("ssh")
	secret := findModule("agent-secret")

	in, err := readInputs(strings.NewReader(`{"inputs":{"mode":" public "}}`+"\n"), ssh)
	if err != nil || in["mode"] != "public" {
		t.Fatalf("got %v, %v", in, err)
	}
	for body, want := range map[string]string{
		"":                                     `needs "mode"`,
		`{"inputs":{"mode":"open"}}`:           "must be one of tailnet-only, public",
		`{"inputs":{"mode":"public","x":"1"}}`: `takes no input "x"`,
		`{"inputs":{"mode":3}}`:                "must be a string",
		"mode=public":                          "must be JSON",
	} {
		if _, err := readInputs(strings.NewReader(body), ssh); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
	// A secret that fails its check never shows in the error.
	_, _, err = secret.build(map[string]string{"secret": "short!"})
	if err == nil || strings.Contains(err.Error(), "short!") {
		t.Errorf("secret check: %v", err)
	}
}

// TestMachineRunSaysWhatHappens: every line a program acts on is ::forge::
// and JSON; a failing step stops the run and says why.
func TestMachineRunSaysWhatHappens(t *testing.T) {
	var out bytes.Buffer
	ran := []string{}
	st := []steps.Step{
		{Name: "first", Run: func(*steps.Context) error { ran = append(ran, "first"); return nil }},
		{Name: "skipped", Skip: func(*steps.Context) bool { return true }, Run: func(*steps.Context) error { ran = append(ran, "skipped"); return nil }},
		{Name: "broken", Run: func(*steps.Context) error { return errors.New("no route to github.com") }},
		{Name: "never", Run: func(*steps.Context) error { ran = append(ran, "never"); return nil }},
	}
	after := false
	m := &module{Name: "test", after: func(map[string]string) { after = true }}

	if code := machineRun(&out, m, nil, st, &steps.Context{}); code != 1 {
		t.Errorf("exit %d", code)
	}
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(line, eventPrefix) {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, eventPrefix)), &e); err != nil {
			t.Fatalf("not JSON: %s", line)
		}
		events = append(events, e)
	}
	got := []string{}
	for _, e := range events {
		got = append(got, e["event"].(string)+":"+asString(e["name"])+":"+asString(e["state"]))
	}
	want := []string{"start::", "step:first:running", "step:first:done", "step:skipped:skipped", "step:broken:running", "step:broken:failed", "done::"}
	if !slices.Equal(got, want) {
		t.Errorf("events:\n%v\nwant\n%v", got, want)
	}
	if last := events[len(events)-1]; last["ok"] != false || events[5]["error"] != "no route to github.com" {
		t.Errorf("end: %v / %v", last, events[5])
	}
	if !slices.Equal(ran, []string{"first"}) || after {
		t.Errorf("ran %v, after %v", ran, after)
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// TestSudoersRule: the rule names forge's machine commands and nothing else,
// and visudo takes it.
func TestSudoersRule(t *testing.T) {
	rule := sudoersFor("deploy", "/usr/local/bin/forge")
	if !strings.Contains(rule, "deploy ALL=(root) NOPASSWD: /usr/local/bin/forge run *, /usr/local/bin/forge status --json, /usr/local/bin/forge audit --json, /usr/local/bin/forge modules --json\n") {
		t.Errorf("rule:\n%s", rule)
	}
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		t.Skip("no visudo here")
	}
	file := filepath.Join(t.TempDir(), "forge-machine")
	if err := os.WriteFile(file, []byte(rule), 0o440); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(visudo, "-cf", file).CombinedOutput(); err != nil {
		t.Errorf("visudo: %s", out)
	}
}

// TestRootOnly: a forge someone else could replace is never let in without a password.
func TestRootOnly(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "forge")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := rootOnly(file); err == nil {
			t.Error("a file of a user's own passed as root-only")
		}
		return
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := rootOnly(file); err == nil {
		t.Error("a folder anyone can write to passed as root-only")
	}
}

// The alerts module changes the name, the logins said and the quiet list
// without handing the bot around again, and refuses what alerts.env, sourced
// by root's scripts, must never hold.
func TestAlertsModuleKeepsTheServersBot(t *testing.T) {
	prev := alerts.EnvPath
	alerts.EnvPath = filepath.Join(t.TempDir(), "alerts.env")
	t.Cleanup(func() { alerts.EnvPath = prev })

	if _, err := alertsConfig(map[string]string{"name": "Votonia"}); err == nil || !strings.Contains(err.Error(), "no Telegram bot yet") {
		t.Fatalf("a server with no bot: %v", err)
	}

	const token = "123456789:AAexampleexampleexampleexampleexample"
	if err := os.WriteFile(alerts.EnvPath, []byte("TELEGRAM_BOT_TOKEN="+token+"\nTELEGRAM_CHAT_ID=42\nALERT_SSH_LOGIN=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := alertsConfig(map[string]string{"name": "Votonia VPS", "quiet": "2.135.53.39, 100.64.0.0/10"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TelegramBotToken != token || cfg.AlertsChatID != "42" || cfg.AlertName != "Votonia VPS" ||
		cfg.AlertLogins != alerts.LoginsNew || strings.Join(cfg.AlertQuietFrom, " ") != "2.135.53.39/32 100.64.0.0/10" {
		t.Fatalf("got %+v", cfg)
	}
	if cfg, _ := alertsConfig(map[string]string{"logins": "off"}); cfg.AlertLogins != alerts.LoginsOff {
		t.Fatalf("logins off: %q", cfg.AlertLogins)
	}

	for _, in := range []map[string]string{
		{"name": "x'; reboot; '"},
		{"name": "$(id)"},
		{"quiet": "$(id)"},
		{"token": "not-a-token"},
		{"chat": "42; rm -rf /"},
	} {
		if _, err := alertsConfig(in); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
}

func setupAnswers(more map[string]string) map[string]string {
	in := map[string]string{"username": "deploy", "password": "s3cret-pass", "admin_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK deploy.me studio-os", "portainer": "off"}
	for k, v := range more {
		in[k] = v
	}
	return in
}

// TestSetupAnswers: the wizard's questions as a program answers them, with the
// wizard's own checks, and an answer can't become more than it says.
func TestSetupAnswers(t *testing.T) {
	cfg, err := setupConfig(setupAnswers(map[string]string{
		"github_repos": "acme/api, acme/web", "hostname": "studio-os", "timezone": "Asia/Almaty", "swap_gb": "4",
		"tailscale": "no", "docker_daemon": "yes", "caddy": "yes", "caddy_repo": "acme/caddy", "projects": "/srv/projects/",
		"firewall": "no", "kernel": "no",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "deploy" || cfg.DeployPassword != "s3cret-pass" || cfg.AdminKeySource != "paste" || !strings.HasPrefix(cfg.AdminKeyValue, "ssh-ed25519 ") {
		t.Errorf("user and key: %+v", cfg)
	}
	if !slices.Equal(cfg.GitHubRepos, []string{"acme/api", "acme/web"}) || cfg.Hostname != "studio-os" || cfg.Timezone != "Asia/Almaty" || cfg.SwapGB != 4 {
		t.Errorf("base: %+v", cfg)
	}
	if cfg.InstallTailscale || cfg.InstallPortainer || cfg.EnableFirewall || cfg.HardenKernel || !cfg.EnableLogRotation {
		t.Errorf("features: %+v", cfg)
	}
	if cfg.CaddyRepo != "acme/caddy" || cfg.CaddyProjects != "/srv/projects" {
		t.Errorf("caddy: %q %q", cfg.CaddyRepo, cfg.CaddyProjects)
	}
	if off, err := setupConfig(setupAnswers(map[string]string{"caddy": "no"})); err != nil || off.CaddyRepo != "" {
		t.Errorf("caddy off: %q, %v", off.CaddyRepo, err)
	}
	if pkg, err := setupConfig(setupAnswers(map[string]string{"caddy": "yes", "caddy_package": "UEsDBA=="})); err != nil || pkg.CaddyRepo != config.CaddyPackage || pkg.CaddyPackageData != "UEsDBA==" {
		t.Errorf("caddy from a package: %q, %v", pkg.CaddyRepo, err)
	}
	if own, err := setupConfig(setupAnswers(map[string]string{"caddy": "yes"})); err != nil || own.CaddyRepo != config.CaddyBuiltin {
		t.Errorf("caddy with no repo named is its image: %q, %v", own.CaddyRepo, err)
	}

	for name, more := range map[string]map[string]string{
		"root as the deploy user":       {"username": "root"},
		"a username that's a command":   {"username": "deploy;reboot"},
		"no key":                        {"admin_key": ""},
		"a key with options in front":   {"admin_key": `command="/bin/sh" ssh-ed25519 AAAAC3Nz x`},
		"two lines of key":              {"admin_key": "ssh-ed25519 AAAAC3Nz x\nssh-ed25519 AAAAC3Ny y"},
		"a timezone that's a path":      {"timezone": "../../etc/passwd"},
		"swap in words":                 {"swap_gb": "two"},
		"a relative projects folder":    {"projects": "srv/projects"},
		"a projects folder climbing up": {"projects": "/srv/../etc"},
		"a top-level projects folder":   {"projects": "/opt"},
		"a repo that isn't one":         {"github_repos": "not a repo"},
		"a caddy repo that isn't one":   {"caddy_repo": "not a repo"},
		"a tailnet agent, no tailscale": {"tailscale": "no", "portainer": "tailnet"},
		"a short AGENT_SECRET":          {"agent_secret": "short"},
		"alerts with no bot":            {"alerts": "yes"},
	} {
		if _, err := setupConfig(setupAnswers(more)); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// TestSetupStepsLeaveSSHDAlone: the setup never closes sshd, whatever it's
// asked: ssh-login does, once the program has proved the new sign-in.
func TestSetupStepsLeaveSSHDAlone(t *testing.T) {
	m := findModule("setup")
	if !m.Internal || !m.Danger || !m.Waits {
		t.Errorf("setup: %+v", m)
	}
	system.DryRun = true
	t.Cleanup(func() { system.DryRun = false })
	st, ctx, err := m.build(setupAnswers(map[string]string{"projects": "/srv/projects", "tailscale": "yes", "tailscale_login": "yes"}))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, s := range st {
		names = append(names, s.Name)
		if strings.Contains(s.Name, "SSH hardening") {
			t.Errorf("setup closes sshd: %s", s.Name)
		}
	}
	if !ctx.TailscaleLogin {
		t.Error("tailscale_login: not asked")
	}
	if !slices.Contains(names, "Create deploy user with sudo + docker access") || !strings.HasPrefix(names[0], "Preflight") {
		t.Errorf("steps: %v", names)
	}
	if !slices.Contains(names, "Projects folder /srv/projects for deploy") || names[len(names)-1] != "Machine access for deploy" {
		t.Errorf("the last steps: %v", names)
	}
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			continue
		}
		if err := s.Run(ctx); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
}

// TestSSHLoginNeedsASetup: closing sign-in needs to know who stays able to
// sign in, and closing root refuses while that user has no key.
func TestSSHLoginNeedsASetup(t *testing.T) {
	if _, err := os.Stat(config.StatePath); err == nil {
		t.Skip("this machine was set up by forge")
	}
	if _, _, err := findModule("ssh-login").build(map[string]string{"root": "off"}); err == nil || !strings.Contains(err.Error(), "wasn't set up by forge") {
		t.Errorf("no state: %v", err)
	}
	cfg := config.Default()
	cfg.Username, cfg.DisableRootLogin = "nobody-with-no-key", true
	st, ctx := steps.SSHLoginSteps(cfg)
	if len(st) != 1 || st[0].Skip != nil {
		t.Fatalf("steps: %+v", st)
	}
	if err := st[0].Run(ctx); err == nil || !strings.Contains(err.Error(), "refusing to close root login") {
		t.Errorf("no key: %v", err)
	}
}
