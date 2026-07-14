// Package system provides thin wrappers around shell execution and host facts
// used by the provisioning steps. Every mutating command flows through Run /
// RunQuiet so that --dry-run can intercept it in a single place.
package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DryRun, when true, makes Run/RunQuiet print the command instead of executing
// it. Read-only helpers (CommandExists, PkgInstalled, FileContains, ReadFile)
// always run for real so dry-run reflects the actual host state.
var DryRun bool

// CommandLog collects every command that Run/RunQuiet was asked to execute.
// Useful for the dry-run summary and for tests.
var CommandLog []string

// Run executes a command, streaming nothing but returning combined output.
// In dry-run mode it records the command and returns empty output.
func Run(name string, args ...string) (string, error) {
	cmdline := name + " " + strings.Join(args, " ")
	CommandLog = append(CommandLog, strings.TrimSpace(cmdline))
	if DryRun {
		return "", nil
	}
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		return buf.String(), fmt.Errorf("%s: %w\n%s", cmdline, err, buf.String())
	}
	return buf.String(), nil
}

// RunRedacted executes name/args like Run but records logline in CommandLog
// instead of the real command line, so secrets passed as arguments never reach
// the log (dry-run output, tests, summaries).
func RunRedacted(logline, name string, args ...string) (string, error) {
	CommandLog = append(CommandLog, logline)
	if DryRun {
		return "", nil
	}
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("%s: %w\n%s", logline, err, buf.String())
	}
	return buf.String(), nil
}

// RunEnv executes like Run but with extra KEY=VALUE entries appended to the
// environment. The values never appear in CommandLog, so it is safe for
// secrets consumed via env (e.g. `docker run -e KEY` without a value).
func RunEnv(env []string, name string, args ...string) (string, error) {
	cmdline := name + " " + strings.Join(args, " ")
	CommandLog = append(CommandLog, strings.TrimSpace(cmdline))
	if DryRun {
		return "", nil
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("%s: %w\n%s", cmdline, err, buf.String())
	}
	return buf.String(), nil
}

// RunShell runs a command through `bash -c`, for pipelines and redirects.
func RunShell(script string) (string, error) {
	CommandLog = append(CommandLog, script)
	if DryRun {
		return "", nil
	}
	cmd := exec.Command("bash", "-c", script)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("bash -c %q: %w\n%s", script, err, buf.String())
	}
	return buf.String(), nil
}

// RunInput runs a command feeding the given string to its stdin (e.g. chpasswd).
// The stdin content is never logged, so it is safe for secrets.
func RunInput(stdin, name string, args ...string) error {
	cmdline := name + " " + strings.Join(args, " ")
	CommandLog = append(CommandLog, strings.TrimSpace(cmdline)+" (stdin hidden)")
	if DryRun {
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w\n%s", cmdline, err, buf.String())
	}
	return nil
}

// CommandExists reports whether a binary is on PATH.
func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// PkgInstalled reports whether a dpkg package is installed.
func PkgInstalled(pkg string) bool {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", pkg).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "install ok installed")
}

// FileContains reports whether path exists and contains the given substring.
func FileContains(path, substr string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), substr)
}

// FileExists reports whether a path exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// WriteFile writes content to a path with the given mode. Honours dry-run.
func WriteFile(path, content string, mode os.FileMode) error {
	CommandLog = append(CommandLog, fmt.Sprintf("write %s (%o)", path, mode))
	if DryRun {
		return nil
	}
	return os.WriteFile(path, []byte(content), mode)
}

// BackupFile copies path to path.bak if no backup exists yet.
func BackupFile(path string) error {
	bak := path + ".bak"
	if FileExists(bak) || !FileExists(path) {
		return nil
	}
	_, err := Run("cp", "-a", path, bak)
	return err
}
