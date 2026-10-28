package steps

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

const (
	etcHosts           = "/etc/hosts"
	cloudInitDir       = "/etc/cloud/cloud.cfg.d"
	cloudInitHostnameF = "/etc/cloud/cloud.cfg.d/99-forge-hostname.cfg"
)

func baseStep() Step {
	return Step{
		Name: "Base system: hostname, timezone, swap, utilities",
		Skip: func(c *Context) bool { return !c.Cfg.EnableBaseTuning },
		Run: func(c *Context) error {
			cfg := c.Cfg

			if cfg.Hostname != "" {
				if err := setHostname(cfg.Hostname); err != nil {
					return err
				}
			}
			if cfg.Timezone != "" {
				if _, err := system.Run("timedatectl", "set-timezone", cfg.Timezone); err != nil {
					return err
				}
			}
			if err := ensureTimeSync(); err != nil {
				return err
			}

			// Handy operator utilities.
			if err := aptInstall("htop", "ncdu", "git", "curl", "vim", "tmux", "unzip", "jq"); err != nil {
				return err
			}

			return ensureSwap(c)
		},
	}
}

// setHostname sets the hostname and makes it stick: /etc/hosts must resolve it
// (otherwise every sudo prints "unable to resolve host"), and on cloud images
// cloud-init would otherwise reset both from instance metadata on next boot.
func setHostname(name string) error {
	if _, err := system.Run("hostnamectl", "set-hostname", name); err != nil {
		return err
	}
	hosts, err := readFileOrEmpty(etcHosts)
	if err != nil {
		return err
	}
	if updated := hostsWithName(hosts, name); updated != hosts {
		if err := system.BackupFile(etcHosts); err != nil {
			return err
		}
		if err := system.WriteFile(etcHosts, updated, 0o644); err != nil {
			return err
		}
	}
	if system.FileExists(cloudInitDir) {
		const cfg = "# Managed by forge: keep the hostname (and /etc/hosts) set by forge across reboots.\n" +
			"preserve_hostname: true\nmanage_etc_hosts: false\n"
		if err := system.WriteFile(cloudInitHostnameF, cfg, 0o644); err != nil {
			return err
		}
	}
	return nil
}

var hostsLoopbackRe = regexp.MustCompile(`(?m)^127\.0\.1\.1[ \t].*$`)

// hostsWithName points the Debian-convention 127.0.1.1 entry at name (adding
// the short name for an FQDN), inserting it after the localhost line when
// absent.
func hostsWithName(hosts, name string) string {
	entry := "127.0.1.1\t" + name
	if short, _, ok := strings.Cut(name, "."); ok {
		entry += " " + short
	}
	if hostsLoopbackRe.MatchString(hosts) {
		return hostsLoopbackRe.ReplaceAllLiteralString(hosts, entry)
	}
	lines := strings.Split(hosts, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "127.0.0.1") {
			lines = append(lines[:i+1], append([]string{entry}, lines[i+1:]...)...)
			return strings.Join(lines, "\n")
		}
	}
	if hosts != "" && !strings.HasSuffix(hosts, "\n") {
		hosts += "\n"
	}
	return hosts + entry + "\n"
}

// timeSyncPkgs are the NTP clients timedatectl can drive. Ubuntu ships
// systemd-timesyncd (chrony since 25.10); minimal Debian may ship none.
var timeSyncPkgs = []string{"systemd-timesyncd", "chrony", "ntpsec", "ntp", "openntpd"}

// ensureTimeSync installs systemd-timesyncd when no NTP client is present, then
// enables synchronisation. TLS, TOTP and log correlation all need a sane clock.
func ensureTimeSync() error {
	have := false
	for _, p := range timeSyncPkgs {
		if pkgInstalled(p) {
			have = true
			break
		}
	}
	if !have {
		if err := aptInstall("systemd-timesyncd"); err != nil {
			return err
		}
	}
	// Best-effort: containers often can't set the clock.
	_, _ = system.Run("timedatectl", "set-ntp", "true")
	return nil
}

// ensureSwap creates and enables a swapfile of the configured size if none is
// active yet. Idempotent: a running swap or existing /swapfile is left alone.
func ensureSwap(c *Context) error {
	if c.Cfg.SwapGB <= 0 {
		return nil
	}
	if c.Container != "" {
		c.Notes = append(c.Notes, "swap skipped — "+c.Container+" containers can't enable swap (ask your provider)")
		return nil
	}
	if system.FileExists("/swapfile") || swapActive() {
		c.Notes = append(c.Notes, "swap already present — left unchanged")
		return nil
	}
	if fs, _ := system.Output("findmnt", "-no", "FSTYPE", "/"); fs == "btrfs" {
		// Copy-on-write files can't back swap; btrfs needs its own tool.
		c.Notes = append(c.Notes, "swap skipped — / is btrfs; create one with `btrfs filesystem mkswapfile --size "+
			fmt.Sprintf("%dg", c.Cfg.SwapGB)+" /swapfile`")
		return nil
	}
	size := fmt.Sprintf("%dG", c.Cfg.SwapGB)
	if _, err := system.Run("fallocate", "-l", size, "/swapfile"); err != nil {
		// Fallback for filesystems without fallocate support.
		if _, err2 := system.Run("dd", "if=/dev/zero", "of=/swapfile", "bs=1M",
			fmt.Sprintf("count=%d", c.Cfg.SwapGB*1024)); err2 != nil {
			return fmt.Errorf("create /swapfile: fallocate: %v; dd: %w", err, err2)
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
		if err := appendLine("/etc/fstab", "/swapfile none swap sw 0 0"); err != nil {
			return err
		}
	}
	return nil
}

func swapActive() bool {
	out, err := system.Output("swapon", "--show", "--noheadings")
	return err == nil && out != ""
}
