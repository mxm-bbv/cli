package steps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/system"
)

// HostKey is one of the server's own keys: what a client checks the server by.
type HostKey struct {
	Type   string `json:"type"`
	Public string `json:"public"`
}

// hostKeyTypes are the ones made again; a DSA key is left as it is (OpenSSH
// no longer uses it).
var hostKeyTypes = []string{"ed25519", "ecdsa", "rsa"}

// RenewHostKeys makes each host key the server has again, the same types, and
// has sshd take them: open sessions stay, the next connection meets the new
// keys. The old ones are kept in /var/lib/forge/host-keys/<time>, and put
// back if sshd won't start with the new ones.
func RenewHostKeys() ([]HostKey, error) {
	ensureSSHDRuntimeDir()
	backup := filepath.Join("/var/lib/forge/host-keys", time.Now().UTC().Format("20060102-150405"))
	return renewHostKeysIn("/etc/ssh", backup,
		func(t, path string) error {
			_, err := system.Run("ssh-keygen", "-q", "-t", t, "-N", "", "-f", path)
			return err
		},
		func() error { _, err := system.Run("sshd", "-t"); return err },
		reloadSSHD)
}

// renewHostKeysIn is RenewHostKeys in dir, with how a key is made, how sshd
// checks its config and how it reloads.
func renewHostKeysIn(dir, backup string, keygen func(t, path string) error, check, reload func() error) ([]HostKey, error) {
	var have []string
	for _, t := range hostKeyTypes {
		if system.FileExists(filepath.Join(dir, "ssh_host_"+t+"_key")) {
			have = append(have, t)
		}
	}
	if len(have) == 0 {
		return nil, errors.New("the server has no host keys in " + dir)
	}
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return nil, err
	}
	files := func(t string) []string {
		p := filepath.Join(dir, "ssh_host_"+t+"_key")
		return []string{p, p + ".pub"}
	}
	for _, t := range have {
		for _, f := range files(t) {
			if err := copyFile(f, filepath.Join(backup, filepath.Base(f))); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
	}
	restore := func() {
		for _, t := range have {
			for _, f := range files(t) {
				_ = copyFile(filepath.Join(backup, filepath.Base(f)), f)
			}
		}
	}

	for _, t := range have {
		for _, f := range files(t) {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				restore()
				return nil, err
			}
		}
		if err := keygen(t, files(t)[0]); err != nil {
			restore()
			return nil, fmt.Errorf("making the %s host key (the old keys are back): %w", t, err)
		}
	}
	if err := check(); err != nil {
		restore()
		return nil, fmt.Errorf("sshd refuses the new host keys, the old ones are back: %w", err)
	}
	if err := reload(); err != nil {
		restore()
		_ = reload()
		return nil, fmt.Errorf("sshd didn't take the new host keys, the old ones are back: %w", err)
	}

	keys := make([]HostKey, 0, len(have))
	for _, t := range have {
		pub, err := os.ReadFile(files(t)[1])
		if err != nil {
			return nil, err
		}
		f := strings.Fields(string(pub))
		if len(f) < 2 {
			return nil, errors.New("unreadable " + files(t)[1])
		}
		keys = append(keys, HostKey{Type: f[0], Public: f[0] + " " + f[1]})
	}
	return keys, nil
}

// reloadSSHD has a running sshd read its host keys again. With socket
// activation and no sshd running yet, the next connection starts one that
// reads them anyway.
func reloadSSHD() error {
	svc := sshServiceName()
	if _, err := system.Run("systemctl", "is-active", "--quiet", svc); err != nil {
		return nil
	}
	_, err := system.Run("systemctl", "reload", svc)
	return err
}

// copyFile copies src to dst with src's mode.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}
