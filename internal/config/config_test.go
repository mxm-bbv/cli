package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"bad username":        func(c *Config) { c.Username = "Bad User" },
		"root as deploy user": func(c *Config) { c.Username = "root" },
		"port zero":           func(c *Config) { c.SSHPort = 0 },
		"port too big":        func(c *Config) { c.SSHPort = 70000 },
		"negative swap":       func(c *Config) { c.SwapGB = -1 },
		"hostname injection":  func(c *Config) { c.Hostname = "web;reboot" },
		"hostname uppercase":  func(c *Config) { c.Hostname = "Web-01" },
		"unknown key source":  func(c *Config) { c.AdminKeySource = "ftp" },
		"unknown agent mode":  func(c *Config) { c.PortainerAccess = "wide-open" },
		"disk pct > 100": func(c *Config) {
			c.EnableAlerts = true
			c.AlertsChatID = "123456"
			c.AlertDiskPercent = 150
		},
		"alerts chat id injection": func(c *Config) {
			c.EnableAlerts = true
			c.AlertsChatID = "1$(reboot)"
		},
	}
	for name, mutate := range cases {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestValidHostname(t *testing.T) {
	for _, ok := range []string{"", "web-01", "web-01.example.com", "a"} {
		if err := ValidHostname(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"-web", "web-", "web..com", "web_01", "a b", strings.Repeat("a", 64)} {
		if err := ValidHostname(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestLoadValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forge.yaml")
	if err := os.WriteFile(path, []byte("username: deploy\nssh_port: 99999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ssh_port") {
		t.Fatalf("expected ssh_port validation error, got %v", err)
	}
}

func TestSaveNeverWritesSecrets(t *testing.T) {
	cfg := Default()
	cfg.DeployPassword = "pw-SECRET"
	cfg.TailscaleAuthKey = "tskey-SECRET"
	cfg.TelegramBotToken = "tg-SECRET"
	path := filepath.Join(t.TempDir(), "forge.yaml")
	if err := Save(cfg, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRET") {
		t.Fatalf("secret serialised:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", info.Mode().Perm())
	}
}
