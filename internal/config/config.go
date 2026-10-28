// Package config holds the wizard answers that drive a provisioning run.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
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

	// GitHub deploy key (clone private repos from the server)
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
	EnableBaseTuning  bool `yaml:"enable_base_tuning"`  // hostname/tz/swap/utils
	EnableLogRotation bool `yaml:"enable_log_rotation"` // docker daemon.json
	InstallPortainer  bool `yaml:"install_portainer"`
	InstallWatchtower bool `yaml:"install_watchtower"`

	// Portainer Agent exposure (see PortainerAccess). TailscaleSSH additionally
	// enables `tailscale up --ssh` so the box stays reachable from the tailnet
	// (e.g. a phone) even if sshd or Portainer are down.
	PortainerAccess PortainerAccess `yaml:"portainer_access"`
	TailscaleSSH    bool            `yaml:"tailscale_ssh"`

	// Telegram alerts: a daily audit sweep, host-health thresholds, and SSH
	// logins are pushed to a Telegram chat. The bot token is a secret and is
	// never serialised; the chat ID is not sensitive.
	EnableAlerts     bool   `yaml:"enable_alerts"`
	AlertsChatID     string `yaml:"alerts_chat_id"`
	AlertOnSSHLogin  bool   `yaml:"alert_on_ssh_login"`
	AlertLoadPerCPU  int    `yaml:"alert_load_per_cpu"` // sustained load/CPU % to warn at (default 90)
	AlertDiskPercent int    `yaml:"alert_disk_percent"` // root fs usage % to warn at (default 85)

	// Runtime-only (not serialised)
	DeployPassword   string `yaml:"-"`
	TailscaleAuthKey string `yaml:"-"` // secret: prompted, never written to disk
	TelegramBotToken string `yaml:"-"` // secret: prompted, never written to disk
}

// Default returns a Config pre-filled with sensible defaults.
func Default() Config {
	return Config{
		Username:          "deploy",
		AdminKeySource:    AdminKeyPaste,
		GenerateGitHubKey: true,
		GitHubKeyComment:  "deploy@server",
		Timezone:          "UTC",
		SwapGB:            2,
		SSHPort:           22,
		DisableRootLogin:  true,
		DisablePassauth:   true,
		EnableFirewall:    true,
		EnableAutoUpdates: true,
		EnableBaseTuning:  true,
		EnableLogRotation: true,
		InstallPortainer:  true,
		InstallWatchtower: false,
		PortainerAccess:   PortainerTailnet,
		TailscaleSSH:      true,
		EnableAlerts:      false,
		AlertOnSSHLogin:   true,
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
	}
	return nil
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
