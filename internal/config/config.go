// Package config holds the wizard answers that drive a provisioning run.
package config

import (
	"os"

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

// Load reads a Config from a YAML file.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
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
