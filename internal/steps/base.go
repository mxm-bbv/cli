package steps

import (
	"fmt"

	"github.com/mxm-bbv/cli/internal/system"
)

func baseStep() Step {
	return Step{
		Name: "Base system: hostname, timezone, swap, utilities",
		Skip: func(c *Context) bool { return !c.Cfg.EnableBaseTuning },
		Run: func(c *Context) error {
			cfg := c.Cfg

			if cfg.Hostname != "" {
				if _, err := system.Run("hostnamectl", "set-hostname", cfg.Hostname); err != nil {
					return err
				}
			}
			if cfg.Timezone != "" {
				if _, err := system.Run("timedatectl", "set-timezone", cfg.Timezone); err != nil {
					return err
				}
			}
			// Enable NTP sync (best-effort; not fatal).
			_, _ = system.Run("timedatectl", "set-ntp", "true")

			// Handy operator utilities.
			if err := aptInstall("htop", "ncdu", "git", "curl", "vim", "tmux", "unzip", "jq"); err != nil {
				return err
			}

			return ensureSwap(c)
		},
	}
}

// ensureSwap creates and enables a swapfile of the configured size if none is
// active yet. Idempotent: a running swap or existing /swapfile is left alone.
func ensureSwap(c *Context) error {
	if c.Cfg.SwapGB <= 0 {
		return nil
	}
	if system.FileExists("/swapfile") || swapActive() {
		c.Notes = append(c.Notes, "swap already present — left unchanged")
		return nil
	}
	size := fmt.Sprintf("%dG", c.Cfg.SwapGB)
	if _, err := system.Run("fallocate", "-l", size, "/swapfile"); err != nil {
		// Fallback for filesystems without fallocate support.
		if _, err2 := system.RunShell(fmt.Sprintf("dd if=/dev/zero of=/swapfile bs=1M count=%d", c.Cfg.SwapGB*1024)); err2 != nil {
			return err
		}
	}
	if _, err := system.Run("chmod", "600", "/swapfile"); err != nil {
		return err
	}
	if _, err := system.Run("mkswap", "/swapfile"); err != nil {
		return err
	}
	if _, err := system.Run("swapon", "/swapfile"); err != nil {
		return err
	}
	if !system.FileContains("/etc/fstab", "/swapfile") {
		if _, err := system.RunShell("echo '/swapfile none swap sw 0 0' >> /etc/fstab"); err != nil {
			return err
		}
	}
	return nil
}

func swapActive() bool {
	out, _ := system.Run("swapon", "--show")
	return len(out) > 0 && !system.DryRun
}
