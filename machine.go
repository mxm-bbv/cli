package main

// forge's machine mode: what a program — deploy.me over ssh, with no
// terminal — can ask of it.
//
//	forge modules --json       the catalog: each module, what it does, its inputs
//	forge run <module>         runs one; its inputs are a JSON object on the first
//	                           line of stdin ({"inputs": {...}}), so a secret never
//	                           shows on a command line; it says what happens as
//	                           lines of ::forge::{json}, other lines are its log
//	forge status --json        what `forge status` shows
//	forge audit --json         every check's result
//	sudo forge machine enable  lets the deploy user run those without a password
//
// A module is one of forge's own commands (forge tailscale, agent-secret,
// github, caddy, ssh …) with its questions as inputs: the same steps, the
// same checks, never anything a person at the server couldn't do.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"

	"github.com/mxm-bbv/cli/internal/alerts"
	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
	"github.com/mxm-bbv/cli/internal/tripwire"
	"github.com/mxm-bbv/cli/internal/update"
)

// eventPrefix starts every line a program reads; the rest is the log.
const eventPrefix = "::forge::"

// moduleInput is one question a module asks.
type moduleInput struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // text, secret (never echoed or logged), choice
	Label    string   `json:"label"`
	Help     string   `json:"help,omitempty"`
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
}

// module is one thing forge does for a program.
type module struct {
	Name        string        `json:"name"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Danger      bool          `json:"danger"`   // changes how the server is reached or what it trusts: ask the person first
	Waits       bool          `json:"waits"`    // waits for a person: a login link or a code to approve
	Internal    bool          `json:"internal"` // a part of something a program does (a move), not a form to show a person
	Inputs      []moduleInput `json:"inputs"`

	build func(in map[string]string) ([]steps.Step, *steps.Context, error)
	// after runs once every step succeeded: what forge remembers about the server.
	after func(in map[string]string)
}

// step wraps work that isn't one of the provisioning steps.
func step(name string, run func() error) []steps.Step {
	return []steps.Step{{Name: name, Run: func(*steps.Context) error { return run() }}}
}

var modules = []module{
	{
		Name:        "tailscale",
		Title:       "Log in to Tailscale",
		Description: "Joins the server to your tailnet with a login link to open, then starts what waited for it: the Portainer Agent on the tailnet address. Safe to run again.",
		Waits:       true,
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			cfg, ok := loadState()
			if !ok {
				cfg.InstallPortainer = false
			}
			cfg.InstallTailscale = true
			st, ctx := steps.TailscaleSteps(cfg)
			return st, ctx, nil
		},
	},
	{
		Name:        "agent-secret",
		Title:       "Portainer Agent: shared AGENT_SECRET",
		Description: "Switches the server's Portainer Agent to the secret your Portainer Server runs with, on the tailnet address only. The server must be logged in to Tailscale.",
		Danger:      true,
		Inputs:      []moduleInput{{Name: "secret", Type: "secret", Label: "AGENT_SECRET", Help: "16–128 characters: letters, digits and ._~+/=-", Required: true}},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			if err := config.ValidAgentSecret(in["secret"]); err != nil {
				return nil, nil, fmt.Errorf("AGENT_SECRET: %w", err)
			}
			if !steps.TailnetUp() {
				return nil, nil, errors.New("this server isn't logged in to Tailscale: run the tailscale module first")
			}
			cfg, _ := loadState()
			cfg.AgentSecret = in["secret"]
			cfg.InstallTailscale, cfg.InstallPortainer, cfg.PortainerAccess = true, true, config.PortainerTailnet
			st, ctx := steps.TailscaleSteps(cfg)
			return st, ctx, nil
		},
	},
	{
		Name:        "agent-remove",
		Title:       "Remove the Portainer Agent",
		Description: "Takes the Portainer Agent off the server — its container, the AGENT_SECRET forge kept and port 9001 in the container firewall — for a server whose containers are managed over SSH instead. forge never starts it again; agent-secret brings it back.",
		Danger:      true,
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			cfg, _ := loadState()
			st, ctx := steps.RemoveAgentSteps(cfg)
			return st, ctx, nil
		},
		after: func(map[string]string) { rememberAgentRemoved() },
	},
	{
		Name:        "github",
		Title:       "GitHub deploy keys",
		Description: "Gives the deploy user a read-only deploy key for each repository, registered through the GitHub API: approve once with a one-time code. git clone git@github.com:owner/repo.git then works on the server.",
		Waits:       true,
		Inputs:      []moduleInput{{Name: "repos", Type: "text", Label: "Repositories", Help: "owner/repo, several separated by spaces or commas", Required: true}},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			repos, err := config.ParseGitHubRepos(in["repos"])
			if err != nil {
				return nil, nil, err
			}
			if len(repos) == 0 {
				return nil, nil, errors.New("name at least one owner/repo")
			}
			cfg, _ := loadState()
			cfg.GitHubRepos = repos
			st, ctx := steps.GitHubSteps(cfg)
			return st, ctx, nil
		},
		after: func(in map[string]string) {
			if saved, ok := loadState(); ok {
				repos, _ := config.ParseGitHubRepos(strings.Join(saved.GitHubRepos, " ") + " " + in["repos"])
				saved.GitHubRepos = repos
				_ = saveState(saved)
			}
		},
	},
	{
		Name:        "caddy",
		Title:       "Caddy web server",
		Description: "Installs or updates the Caddy setup from your repository on :80/:443, with the proxy-network its sites reach containers on.",
		Inputs:      []moduleInput{{Name: "repo", Type: "text", Label: "Caddy repository", Help: "owner/repo with a docker-compose.prod.yml; empty keeps the one set up before"}},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			cfg, _ := loadState()
			switch {
			case in["repo"] != "":
				cfg.CaddyRepo = in["repo"]
			case cfg.CaddyRepo == "":
				cfg.CaddyRepo = config.DefaultCaddyRepo
			}
			if err := config.ValidGitHubRepo(cfg.CaddyRepo); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", cfg.CaddyRepo, err)
			}
			st, ctx := steps.CaddySteps(cfg)
			return st, ctx, nil
		},
		after: func(in map[string]string) {
			if saved, ok := loadState(); ok && in["repo"] != "" {
				saved.CaddyRepo = in["repo"]
				_ = saveState(saved)
			}
		},
	},
	{
		Name:        "ssh",
		Title:       "SSH from the internet",
		Description: "Closes SSH to the internet so only Tailscale reaches it, or opens it again. Closing refuses unless this very connection comes over Tailscale and the server's Tailscale key never expires.",
		Danger:      true,
		Inputs:      []moduleInput{{Name: "mode", Type: "choice", Label: "SSH answers", Required: true, Options: []string{"tailnet-only", "public"}}},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			if in["mode"] == "public" {
				return step("SSH open to the internet again (key-only, fail2ban)", func() error { return steps.SetSSHTailnetOnly(false) }), &steps.Context{}, nil
			}
			return step("SSH only over Tailscale", func() error {
				if _, err := steps.CheckTailnetOnly(); err != nil {
					return err
				}
				return steps.SetSSHTailnetOnly(true)
			}), &steps.Context{}, nil
		},
		after: func(in map[string]string) { rememberSSHTailnetOnly(in["mode"] == "tailnet-only") },
	},
	{
		Name:        "tripwire-baseline",
		Title:       "Tripwire: accept the server as it is",
		Description: "Records the tripwire's baseline again: what changed since the last one is no longer reported. Only once you know every change was yours.",
		Danger:      true,
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			if !tripwire.Installed() {
				return nil, nil, errors.New("the tripwire isn't set up on this server (it comes with Telegram alerts)")
			}
			return step("Record the tripwire's baseline", func() error {
				if tripwire.Run(true) != 0 {
					return errors.New("the tripwire couldn't record the baseline")
				}
				return nil
			}), &steps.Context{}, nil
		},
	},
	{
		Name:        "alerts",
		Title:       "Telegram alerts",
		Description: "Where this server's alerts go and which SSH logins are worth a message: a user's first from an address each day (the rest go to a daily summary), every one, or none. Logins from quiet addresses only count in the summary, and more than 12 alerts in an hour wait for it too — never the tripwire or the audit.",
		Danger:      true, // it can mute what would tell you about an intruder
		Inputs: []moduleInput{
			{Name: "token", Type: "secret", Label: "Bot token", Help: "from @BotFather; empty keeps the bot this server has"},
			{Name: "chat", Type: "text", Label: "Chat ID", Help: "a number (-100… for a group) or @channel; empty keeps this server's"},
			{Name: "name", Type: "text", Label: "Name in messages", Help: "every alert starts with it; empty: the hostname"},
			{Name: "logins", Type: "choice", Label: "SSH logins", Options: []string{alerts.LoginsNew, alerts.LoginsAll, alerts.LoginsOff}},
			{Name: "quiet", Type: "text", Label: "Quiet addresses", Help: "IPs or networks whose logins only count in the summary, e.g. 203.0.113.7 100.64.0.0/10"},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			cfg, err := alertsConfig(in)
			if err != nil {
				return nil, nil, err
			}
			st, ctx := steps.AlertsSteps(cfg)
			return st, ctx, nil
		},
		after: func(in map[string]string) {
			cfg, err := alertsConfig(in)
			if err != nil {
				return
			}
			saved, ok := loadState()
			if !ok {
				return
			}
			saved.EnableAlerts, saved.AlertsChatID = true, cfg.AlertsChatID
			saved.AlertName, saved.AlertLogins, saved.AlertQuietFrom = cfg.AlertName, cfg.AlertLogins, cfg.AlertQuietFrom
			saved.AlertOnSSHLogin = cfg.AlertLogins != alerts.LoginsOff
			_ = saveState(saved)
		},
	},
	{
		Name:        "update-images",
		Title:       "Re-pull forge's pinned images",
		Description: "Pulls the Portainer Agent and Watchtower at the versions this forge pins, and recreates the ones that drifted.",
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			return step("Pinned images", func() error {
				if update.Images() != 0 {
					return errors.New("not every image could be updated")
				}
				return nil
			}), &steps.Context{}, nil
		},
	},
	{
		Name:        "update",
		Title:       "Update forge",
		Description: "Replaces this forge with the latest release, after checking its minisign signature and checksum. Fails closed.",
		build: func(map[string]string) ([]steps.Step, *steps.Context, error) {
			return step("forge itself", func() error {
				if update.SelfUpdate(false) != 0 {
					return errors.New("the update didn't go through (signature, checksum or download)")
				}
				return nil
			}), &steps.Context{}, nil
		},
	},
}

// alertsConfig is the alerts module's inputs over what the server has: an
// empty token or chat keeps the server's own, so a program can change the
// name or the quiet list without handing the bot around again.
func alertsConfig(in map[string]string) (config.Config, error) {
	cfg, _ := loadState()
	cur := alerts.ReadEnv()
	cfg.TelegramBotToken = firstOf(in["token"], cur["TELEGRAM_BOT_TOKEN"])
	cfg.AlertsChatID = firstOf(in["chat"], cur["TELEGRAM_CHAT_ID"], cfg.AlertsChatID)
	if cfg.TelegramBotToken == "" || cfg.AlertsChatID == "" {
		return cfg, errors.New("this server has no Telegram bot yet: give the bot token and the chat ID")
	}
	if err := config.ValidTelegramToken(cfg.TelegramBotToken); err != nil {
		return cfg, err
	}
	if err := config.ValidTelegramChatID(cfg.AlertsChatID); err != nil {
		return cfg, err
	}
	if err := config.ValidAlertName(in["name"]); err != nil {
		return cfg, fmt.Errorf("name: %w", err)
	}
	cfg.AlertName = in["name"]
	cfg.AlertLogins = alerts.LoginsNew
	switch {
	case in["logins"] != "":
		cfg.AlertLogins = in["logins"]
	case cur != nil:
		cfg.AlertLogins = alerts.LoginMode(cur["ALERT_SSH_LOGIN"])
	}
	quiet, err := alerts.ParseQuiet(in["quiet"])
	if err != nil {
		return cfg, err
	}
	cfg.AlertQuietFrom = nil
	for _, p := range quiet {
		cfg.AlertQuietFrom = append(cfg.AlertQuietFrom, p.String())
	}
	return cfg, nil
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func findModule(name string) *module {
	for i := range modules {
		if modules[i].Name == name {
			return &modules[i]
		}
	}
	return nil
}

// emit prints one event line.
func emit(w io.Writer, event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	out, _ := json.Marshal(fields)
	fmt.Fprintln(w, eventPrefix+string(out))
}

// runModules is `forge modules [--json]`.
func runModules(args []string) int {
	if slices.Contains(args, "--json") {
		list := slices.Clone(modules)
		for i := range list {
			if list[i].Inputs == nil {
				list[i].Inputs = []moduleInput{}
			}
		}
		out, _ := json.Marshal(map[string]any{"v": 1, "forge": version, "modules": list})
		fmt.Println(string(out))
		return 0
	}
	for _, m := range modules {
		fmt.Printf("  %-18s %s\n", m.Name, m.Title)
	}
	fmt.Println("\n  sudo forge run <module>   with its inputs as JSON on stdin: {\"inputs\": {…}}")
	return 0
}

// readInputs takes the module's inputs from the first line of r and checks
// them. A secret is never part of an error.
func readInputs(r io.Reader, m *module) (map[string]string, error) {
	in := map[string]string{}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if strings.TrimSpace(line) != "" {
		var body struct {
			Inputs map[string]any `json:"inputs"`
		}
		if err := json.Unmarshal([]byte(line), &body); err != nil {
			return nil, errors.New(`the first line of stdin must be JSON: {"inputs": {…}}`)
		}
		for k, v := range body.Inputs {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("input %q must be a string", k)
			}
			in[k] = strings.TrimSpace(s)
		}
	}
	known := map[string]bool{}
	for _, q := range m.Inputs {
		known[q.Name] = true
		v := in[q.Name]
		if q.Required && v == "" {
			return nil, fmt.Errorf("%s needs %q", m.Name, q.Name)
		}
		if q.Type == "choice" && v != "" && !slices.Contains(q.Options, v) {
			return nil, fmt.Errorf("%q must be one of %s", q.Name, strings.Join(q.Options, ", "))
		}
	}
	for k := range in {
		if !known[k] {
			return nil, fmt.Errorf("%s takes no input %q", m.Name, k)
		}
	}
	return in, nil
}

// runModule is `forge run <module>`.
func runModule(args []string) int {
	out := os.Stdout
	// Its stdin and stdout are rsync's own stream: no inputs, no events.
	if len(args) > 0 && args[0] == "move-receive" {
		return moveReceive(args[1:])
	}
	if len(args) == 0 {
		emit(out, "done", map[string]any{"ok": false, "error": "usage: forge run <module> (forge modules lists them)"})
		return 2
	}
	m := findModule(args[0])
	if m == nil {
		emit(out, "done", map[string]any{"ok": false, "error": "no module " + args[0] + " in forge " + version + " (forge modules lists them)"})
		return 2
	}
	if os.Geteuid() != 0 {
		emit(out, "done", map[string]any{"ok": false, "error": "forge run needs root: sudo forge run " + m.Name})
		return 1
	}

	var stdin io.Reader = os.Stdin
	if term.IsTerminal(os.Stdin.Fd()) {
		// A person at a terminal has forge's own commands; nothing to read here.
		stdin = strings.NewReader("")
	}
	in, err := readInputs(stdin, m)
	if err == nil {
		var st []steps.Step
		var ctx *steps.Context
		if st, ctx, err = m.build(in); err == nil {
			return machineRun(out, m, in, st, ctx)
		}
	}
	emit(out, "done", map[string]any{"ok": false, "error": err.Error()})
	return 2
}

// machineRun runs the steps, saying as it goes what each one does, any link
// or code a person must act on, and the last line of the command at work.
func machineRun(out io.Writer, m *module, in map[string]string, st []steps.Step, ctx *steps.Context) int {
	defer system.StopWaiting()
	defer steps.Cleanup()
	logPath := openLog(false)

	names := make([]string, len(st))
	for i, s := range st {
		names[i] = s.Name
	}
	emit(out, "start", map[string]any{"module": m.Name, "forge": version, "steps": names})

	ok := true
	for _, s := range st {
		if s.Skip != nil && s.Skip(ctx) {
			emit(out, "step", map[string]any{"name": s.Name, "state": "skipped"})
			continue
		}
		emit(out, "step", map[string]any{"name": s.Name, "state": "running"})
		done := make(chan error, 1)
		go func() { done <- s.Run(ctx) }()

		tick := time.NewTicker(500 * time.Millisecond)
		attention, activity := "", ""
		var err error
	wait:
		for {
			select {
			case err = <-done:
				break wait
			case <-tick.C:
				if a := system.CurrentAttention(); a != nil && a.Title+a.URL+a.Code != attention {
					attention = a.Title + a.URL + a.Code
					emit(out, "attention", map[string]any{"title": a.Title, "url": a.URL, "code": a.Code, "hint": a.Hint})
				} else if a == nil && attention != "" {
					attention = ""
					emit(out, "attention", map[string]any{"cleared": true})
				}
				if line := system.Activity(); line != activity {
					activity = line
					emit(out, "activity", map[string]any{"line": line})
				}
			}
		}
		tick.Stop()
		if err != nil {
			emit(out, "step", map[string]any{"name": s.Name, "state": "failed", "error": err.Error()})
			ok = false
			break
		}
		emit(out, "step", map[string]any{"name": s.Name, "state": "done"})
	}

	if ok {
		if m.after != nil {
			m.after(in)
		}
		// What forge just changed is not an intrusion.
		if !system.DryRun && tripwire.Installed() && m.Name != "tripwire-baseline" {
			tripwire.Run(true)
		}
	}
	notes := ctx.Notes
	if notes == nil {
		notes = []string{}
	}
	done := map[string]any{"ok": ok, "notes": notes, "tailnet_ip": ctx.TailnetIP, "log": logPath}
	if ctx.Result != nil {
		done["result"] = ctx.Result
	}
	emit(out, "done", done)
	if !ok {
		return 1
	}
	return 0
}

// machineSudoers is where `forge machine enable` lets the deploy user in.
const machineSudoers = "/etc/sudoers.d/forge-machine"

// sudoersFor is the rule: forge's machine-mode commands, nothing else, as root,
// without a password.
func sudoersFor(user, exe string) string {
	return fmt.Sprintf("# forge machine mode (sudo forge machine enable): %[1]s runs forge's modules and reads\n"+
		"# its status without a password, as deploy.me does over ssh. Remove: sudo forge machine disable\n"+
		"%[1]s ALL=(root) NOPASSWD: %[2]s run *, %[2]s status --json, %[2]s audit --json, %[2]s modules --json\n", user, exe)
}

// rootOnly reports why path (or its folder) isn't safe to run as root
// without a password: someone other than root could replace it.
func rootOnly(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must belong to root and be writable by root alone", p)
		}
	}
	return nil
}

// runMachineAccess is `forge machine [enable [user] | disable]`.
func runMachineAccess(args []string) int {
	if !requireRoot("machine " + strings.Join(args, " ")) {
		return 1
	}
	action := ""
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "":
		if data, err := os.ReadFile(machineSudoers); err == nil {
			fmt.Print("  Machine mode is on:\n\n" + string(data))
		} else {
			fmt.Println("  Machine mode is off. sudo forge machine enable [user] turns it on.")
		}
		return 0
	case "disable":
		if err := os.Remove(machineSudoers); err != nil && !os.IsNotExist(err) {
			fmt.Println("  " + err.Error())
			return 1
		}
		fmt.Println("  Machine mode is off: forge asks for the password again.")
		return 0
	case "enable":
		cfg, _ := loadState()
		user := cfg.Username
		if len(args) > 1 {
			user = args[1]
		}
		if err := config.ValidUsername(user); err != nil || user == "root" {
			fmt.Println("  usage: sudo forge machine enable [user] — the user deploy.me connects as")
			return 2
		}
		if _, err := system.Output("id", "-u", user); err != nil {
			fmt.Println("  there's no user " + user + " on this server")
			return 1
		}
		exe, err := os.Executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err == nil {
			err = rootOnly(exe)
		}
		if err != nil {
			fmt.Println("  Not turning machine mode on: " + err.Error())
			return 1
		}
		tmp := machineSudoers + ".new"
		if err := os.WriteFile(tmp, []byte(sudoersFor(user, exe)), 0o440); err != nil {
			fmt.Println("  " + err.Error())
			return 1
		}
		if out, err := system.CombinedOutput("visudo", "-cf", tmp); err != nil {
			_ = os.Remove(tmp)
			fmt.Println("  visudo refused the rule: " + strings.TrimSpace(out))
			return 1
		}
		if err := os.Rename(tmp, machineSudoers); err != nil {
			fmt.Println("  " + err.Error())
			return 1
		}
		fmt.Println("  Machine mode is on: " + user + " runs forge's modules without a password (sudo forge machine disable).")
		return 0
	}
	fmt.Println("  usage: sudo forge machine [enable [user] | disable]")
	return 2
}
