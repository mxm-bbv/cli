// Package config holds the wizard answers that drive a provisioning run.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mxm-bbv/cli/internal/alerts"
)

// PortainerAccess selects how the Portainer Agent is reachable. A publicly
// published agent (0.0.0.0:9001) is a known root-compromise vector, so the
// default binds it to the Tailscale interface only.
type PortainerAccess string

const (
	PortainerTailnet PortainerAccess = "tailnet" // bound to the Tailscale IP only
	PortainerPublic  PortainerAccess = "public"  // bound to 0.0.0.0 — discouraged
)

// AdminKeySource describes how the administrator's public key is obtained.
type AdminKeySource string

const (
	AdminKeyPaste  AdminKeySource = "paste"  // pasted directly into the wizard
	AdminKeyFile   AdminKeySource = "file"   // read from a local file path
	AdminKeyGitHub AdminKeySource = "github" // fetched from https://github.com/<user>.keys
	AdminKeySkip   AdminKeySource = "skip"   // do not configure authorized_keys
)

// Config is the full set of answers collected from the wizard (or loaded from
// a YAML file). It is intentionally serialisable so a run can be replayed with
// --config. The deploy password is deliberately NOT part of this struct so it
// never lands on disk; it is carried separately at runtime.
type Config struct {
	// Deploy user
	Username string `yaml:"username"`

	// Admin SSH access (login to the box as the deploy user)
	AdminKeySource AdminKeySource `yaml:"admin_key_source"`
	AdminKeyValue  string         `yaml:"admin_key_value"` // path, github user, or the key itself

	// GitHub access for cloning private repos from the server. GitHubRepos
	// get one read-only deploy key each, registered through the GitHub API.
	// GenerateGitHubKey is the older manual path: one key the user pastes
	// into GitHub themselves.
	GitHubRepos []string `yaml:"github_repos,omitempty"`
	// CaddyRepo is the operator's Caddy setup (a repo with a
	// docker-compose.prod.yml), run as the box's web server. "" = none.
	CaddyRepo         string `yaml:"caddy_repo"`
	GenerateGitHubKey bool   `yaml:"generate_github_key"`
	GitHubKeyComment  string `yaml:"github_key_comment"`

	// Base system tuning
	Hostname string `yaml:"hostname"`
	Timezone string `yaml:"timezone"`
	SwapGB   int    `yaml:"swap_gb"` // 0 disables swap creation

	// SSH hardening
	SSHPort          int  `yaml:"ssh_port"`
	DisableRootLogin bool `yaml:"disable_root_login"`
	DisablePassauth  bool `yaml:"disable_password_auth"`

	// Optional feature toggles
	EnableFirewall    bool `yaml:"enable_firewall"`     // UFW + fail2ban + DOCKER-USER
	EnableAutoUpdates bool `yaml:"enable_auto_updates"` // unattended-upgrades
	AutoReboot        bool `yaml:"auto_reboot"`         // …and reboot at 04:00 when an update needs it
	EnableBaseTuning  bool `yaml:"enable_base_tuning"`  // hostname/tz/swap/utils
	EnableLogRotation bool `yaml:"enable_log_rotation"` // docker daemon.json
	HardenKernel      bool `yaml:"harden_kernel"`       // sysctl: redirects, source routing, BPF, kptr
	InstallPortainer  bool `yaml:"install_portainer"`
	InstallWatchtower bool `yaml:"install_watchtower"`

	// Tailscale is installed during setup; logging in is a separate, later
	// step (`forge tailscale`) unless an auth key is supplied. TailscaleSSH
	// adds `--ssh` at login, so the box stays reachable from the tailnet (e.g.
	// a phone) even if sshd or Portainer are down. In tailnet mode the
	// Portainer Agent waits for that login, since it binds to the tailnet IP.
	InstallTailscale bool            `yaml:"install_tailscale"`
	SSHTailnetOnly   bool            `yaml:"ssh_tailnet_only"` // set by `forge ssh tailnet-only`, never by the wizard
	PortainerAccess  PortainerAccess `yaml:"portainer_access"`
	TailscaleSSH     bool            `yaml:"tailscale_ssh"`

	// Telegram alerts: a daily audit sweep, host-health thresholds, and SSH
	// logins are pushed to a Telegram chat. The bot token is a secret and is
	// never serialised; the chat ID is not sensitive.
	EnableAlerts    bool   `yaml:"enable_alerts"`
	AlertsChatID    string `yaml:"alerts_chat_id"`
	AlertOnSSHLogin bool   `yaml:"alert_on_ssh_login"`
	// AlertLogins says which SSH logins are worth a message: new (a user's
	// first from an address in a day, the rest in the daily summary), all or
	// off; "" follows alert_on_ssh_login. AlertQuietFrom's logins (IPs or
	// networks) only count in the summary; AlertName starts every message.
	AlertLogins      string   `yaml:"alert_logins,omitempty"`
	AlertQuietFrom   []string `yaml:"alert_quiet_from,omitempty"`
	AlertName        string   `yaml:"alert_name,omitempty"`
	Tripwire         bool     `yaml:"tripwire"`           // minute-by-minute alert on what intruders change
	AlertLoadPerCPU  int      `yaml:"alert_load_per_cpu"` // sustained load/CPU % to warn at (default 90)
	AlertDiskPercent int      `yaml:"alert_disk_percent"` // root fs usage % to warn at (default 85)

	// Runtime-only (not serialised)
	DeployPassword   string `yaml:"-"`
	TailscaleAuthKey string `yaml:"-"` // secret: from $TS_AUTHKEY, never written to disk
	// AgentSecret is the Portainer Agent's AGENT_SECRET. A Portainer Server
	// takes ONE secret (its own AGENT_SECRET env) for all its agents, so every
	// server gets the same one. "" = keep this box's, or generate the first.
	AgentSecret      string `yaml:"-"`
	TelegramBotToken string `yaml:"-"` // secret: prompted, never written to disk
}

// Default returns a Config pre-filled with sensible defaults.
func Default() Config {
	return Config{
		Username:          "deploy",
		AdminKeySource:    AdminKeyPaste,
		GitHubKeyComment:  "deploy@server",
		CaddyRepo:         DefaultCaddyRepo,
		Timezone:          "UTC",
		SwapGB:            2,
		SSHPort:           22,
		DisableRootLogin:  true,
		DisablePassauth:   true,
		EnableFirewall:    true,
		EnableAutoUpdates: true,
		AutoReboot:        true,
		EnableBaseTuning:  true,
		EnableLogRotation: true,
		HardenKernel:      true,
		InstallPortainer:  true,
		InstallWatchtower: false,
		InstallTailscale:  true,
		PortainerAccess:   PortainerTailnet,
		TailscaleSSH:      true,
		EnableAlerts:      false,
		AlertOnSSHLogin:   true,
		Tripwire:          true,
		AlertLoadPerCPU:   90,
		AlertDiskPercent:  85,
	}
}

// Load reads a Config from a YAML file and validates it, so a bad value fails
// before anything runs instead of halfway through provisioning.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

// usernameRe restricts the deploy username to a POSIX- and shell-safe set.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidUsername reports whether name is a safe Linux username.
func ValidUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return errors.New("must be lowercase, start with a letter/underscore, and contain only a-z 0-9 _ - (max 32)")
	}
	return nil
}

// hostLabelRe is one RFC 1123 hostname label.
var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname accepts an RFC 1123 hostname or FQDN (lowercase). Empty means
// "leave as-is" and is valid.
func ValidHostname(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 253 {
		return errors.New("hostname is longer than 253 characters")
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabelRe.MatchString(label) {
			return errors.New("use lowercase letters, digits and '-' (labels of 1-63 chars, separated by dots)")
		}
	}
	return nil
}

// ValidPort reports whether p is a usable TCP port.
func ValidPort(p int) error {
	if p < 1 || p > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

var (
	telegramTokenRe  = regexp.MustCompile(`^[0-9]{5,}:[A-Za-z0-9_-]{30,}$`)
	telegramChatIDRe = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// ValidTelegramToken checks the shape of a BotFather token ("123456:ABC…").
func ValidTelegramToken(tok string) error {
	if !telegramTokenRe.MatchString(tok) {
		return errors.New("bot token should look like 123456789:AA… (from @BotFather)")
	}
	return nil
}

// ValidTelegramChatID accepts a numeric chat ID (negative for groups) or a
// public @channelname.
func ValidTelegramChatID(id string) error {
	if !telegramChatIDRe.MatchString(id) {
		return errors.New("chat ID should be a number (e.g. 123456789, or -100… for groups) or @channelname")
	}
	return nil
}

// Validate checks every field that drives a command, so replayed configs get
// the same guarantees as the interactive wizard.
func (c Config) Validate() error {
	if err := ValidUsername(c.Username); err != nil {
		return fmt.Errorf("username %q: %w", c.Username, err)
	}
	if c.Username == "root" {
		return errors.New("username: the deploy user must not be root")
	}
	if err := ValidHostname(c.Hostname); err != nil {
		return fmt.Errorf("hostname %q: %w", c.Hostname, err)
	}
	if err := ValidPort(c.SSHPort); err != nil {
		return fmt.Errorf("ssh_port %d: %w", c.SSHPort, err)
	}
	if c.SwapGB < 0 || c.SwapGB > 128 {
		return fmt.Errorf("swap_gb %d: must be between 0 and 128", c.SwapGB)
	}
	switch c.AdminKeySource {
	case AdminKeyPaste, AdminKeyFile, AdminKeyGitHub, AdminKeySkip:
	default:
		return fmt.Errorf("admin_key_source %q: must be one of paste, file, github, skip", c.AdminKeySource)
	}
	if c.InstallPortainer {
		switch c.PortainerAccess {
		case PortainerTailnet, PortainerPublic:
		default:
			return fmt.Errorf("portainer_access %q: must be tailnet or public", c.PortainerAccess)
		}
		if c.PortainerAccess == PortainerTailnet && !c.InstallTailscale {
			return errors.New("portainer_access tailnet needs install_tailscale")
		}
	}
	if c.CaddyRepo != "" {
		if err := ValidGitHubRepo(c.CaddyRepo); err != nil {
			return fmt.Errorf("caddy_repo %q: %w", c.CaddyRepo, err)
		}
	}
	for _, r := range c.GitHubRepos {
		if err := ValidGitHubRepo(r); err != nil {
			return fmt.Errorf("github_repos %q: %w", r, err)
		}
	}
	if c.EnableAlerts {
		if c.AlertLoadPerCPU < 1 || c.AlertLoadPerCPU > 1000 {
			return fmt.Errorf("alert_load_per_cpu %d: must be between 1 and 1000", c.AlertLoadPerCPU)
		}
		if c.AlertDiskPercent < 1 || c.AlertDiskPercent > 100 {
			return fmt.Errorf("alert_disk_percent %d: must be between 1 and 100", c.AlertDiskPercent)
		}
		if err := ValidTelegramChatID(c.AlertsChatID); err != nil {
			return fmt.Errorf("alerts_chat_id %q: %w", c.AlertsChatID, err)
		}
		if err := ValidAlertName(c.AlertName); err != nil {
			return fmt.Errorf("alert_name %q: %w", c.AlertName, err)
		}
		switch c.AlertLogins {
		case "", alerts.LoginsNew, alerts.LoginsAll, alerts.LoginsOff:
		default:
			return fmt.Errorf("alert_logins %q: must be new, all or off", c.AlertLogins)
		}
		if _, err := alerts.ParseQuiet(strings.Join(c.AlertQuietFrom, " ")); err != nil {
			return fmt.Errorf("alert_quiet_from: %w", err)
		}
	}
	return nil
}

// LoginAlerts is which SSH logins are worth a message: new, all or off.
func (c Config) LoginAlerts() string {
	if c.AlertLogins != "" {
		return c.AlertLogins
	}
	if c.AlertOnSSHLogin {
		return alerts.LoginsNew
	}
	return alerts.LoginsOff
}

// alertNameRe: what alerts.env can hold in single quotes and a shell can
// source safely — no quote, no newline, no $ or backtick.
var alertNameRe = regexp.MustCompile(`^[\p{L}\p{N} ._()#+-]{0,40}$`)

// ValidAlertName checks the name every alert starts with ("" = the hostname).
func ValidAlertName(name string) error {
	if !alertNameRe.MatchString(name) {
		return errors.New("up to 40 letters, digits, spaces and . _ ( ) # + -")
	}
	return nil
}

// DefaultCaddyRepo is the author's shared Caddy setup, offered by the wizard.
const DefaultCaddyRepo = "MR-Studio-KZ-UA/caddy-core"

// StatePath is where a provisioning run keeps its answers (secrets excluded),
// so later commands — `forge tailscale`, `forge github` — act on the same
// setup without asking again.
const StatePath = "/etc/forge/config.yaml"

var githubRepoRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

var agentSecretRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{16,128}$`)

// ValidAgentSecret accepts "" (generate/keep) or a 16+ character secret.
func ValidAgentSecret(s string) error {
	if s != "" && !agentSecretRe.MatchString(s) {
		return errors.New("16–128 characters: letters, digits and ._~+/=-")
	}
	return nil
}

// ValidGitHubRepo checks an "owner/repo" name.
func ValidGitHubRepo(s string) error {
	if !githubRepoRe.MatchString(s) || strings.HasSuffix(s, ".git") || strings.Contains(s, "/.") {
		return errors.New("must look like owner/repo")
	}
	return nil
}

// ParseGitHubRepos splits a comma/space separated list of owner/repo names,
// accepting pasted GitHub URLs (https://github.com/o/r, git@github.com:o/r.git).
func ParseGitHubRepos(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		f = strings.TrimSuffix(strings.TrimSuffix(f, "/"), ".git")
		for _, p := range []string{"https://github.com/", "http://github.com/", "git@github.com:", "ssh://git@github.com/", "github.com/"} {
			f = strings.TrimPrefix(f, p)
		}
		if err := ValidGitHubRepo(f); err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		if k := strings.ToLower(f); !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// Save writes the Config to a YAML file. The deploy password is excluded by the
// `yaml:"-"` tag, so secrets never reach disk.
func Save(cfg Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// HomeDir returns the home directory path for the deploy user.
func (c Config) HomeDir() string {
	if c.Username == "root" {
		return "/root"
	}
	return "/home/" + c.Username
}
