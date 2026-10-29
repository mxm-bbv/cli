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

	"github.com/mxm-bbv/cli/internal/steps"
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
	for _, name := range []string{"tailscale", "agent-secret", "agent-remove", "github", "caddy", "ssh", "tripwire-baseline", "update"} {
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
