package steps

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// This file centralises every supply-chain trust anchor. Changing any constant
// here is a deliberate, auditable act — reviewers should scrutinise diffs to it.

const (
	dockerGPGFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

	githubHostKeyFP = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"

	portainerAgentImage = "portainer/agent:2.21.5"
	watchtowerImage     = "containrrr/watchtower:1.7.1"
)

// usernameRe restricts the deploy username to a POSIX- and shell-safe set.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidUsername reports whether name is a safe Linux username.
func ValidUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return errors.New("must be lowercase, start with a letter/underscore, and contain only a-z 0-9 _ - (max 32)")
	}
	return nil
}

// githubUserRe follows GitHub's username rules (alphanumeric plus hyphens).
var githubUserRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

// verifyDockerKey checks the downloaded Docker apt key against the pinned
// fingerprint, deleting it and erroring out on mismatch.
func verifyDockerKey(path string) error {
	if system.DryRun {
		return nil
	}
	out, err := system.Run("gpg", "--show-keys", "--with-colons", path)
	if err != nil {
		return fmt.Errorf("verify docker key: %w", err)
	}
	if !strings.Contains(strings.ToUpper(out), dockerGPGFingerprint) {
		_ = os.Remove(path)
		return fmt.Errorf("Docker GPG key fingerprint mismatch — refusing to trust %s (expected %s)", path, dockerGPGFingerprint)
	}
	return nil
}

// verifiedGitHubHostKey runs ssh-keyscan and verifies the ed25519 host key
// against the pinned fingerprint before returning the known_hosts line.
func verifiedGitHubHostKey() (string, error) {
	if system.DryRun {
		return "github.com ssh-ed25519 <pinned on real run>", nil
	}
	scanned, err := system.Run("ssh-keyscan", "-t", "ed25519", "github.com")
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan github.com: %w", err)
	}
	var entry string
	for _, l := range strings.Split(scanned, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "github.com") {
			entry = l
			break
		}
	}
	if entry == "" {
		return "", errors.New("ssh-keyscan returned no github.com host key")
	}

	tmp, err := os.CreateTemp("", "ghhost-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(entry + "\n"); err != nil {
		return "", err
	}
	tmp.Close()

	fpOut, err := system.Run("ssh-keygen", "-lf", tmp.Name())
	if err != nil {
		return "", fmt.Errorf("fingerprint github host key: %w", err)
	}
	if !strings.Contains(fpOut, githubHostKeyFP) {
		return "", fmt.Errorf("GitHub host key fingerprint mismatch — aborting (expected %s, got %q)", githubHostKeyFP, strings.TrimSpace(fpOut))
	}
	return entry, nil
}

// hasAuthorizedKey reports whether the authorized_keys file has at least one
// plausible SSH public key — used to prevent a lockout before disabling
// password/root SSH auth.
func hasAuthorizedKey(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "ssh-") || strings.HasPrefix(l, "ecdsa-") || strings.HasPrefix(l, "sk-") {
			return true
		}
	}
	return false
}
