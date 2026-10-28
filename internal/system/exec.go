// Package system provides thin wrappers around shell execution and host facts
// used by the provisioning steps. Every mutating command flows through these
// helpers so that dry-run, live output, logging and per-command timeouts are
// handled in exactly one place.
package system

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DryRun, when true, records commands instead of executing them. Read-only
// helpers (CommandExists, PkgInstalled, FileContains, …) always run for real so
// dry-run reflects actual host state.
var DryRun bool

// CommandLog collects every command Run/RunShell was asked to execute.
var CommandLog []string

// LogWriter, when set, receives the full stdout+stderr of every command plus a
// "$ <cmd>" header — this is the on-disk transcript the user can tail.
var LogWriter io.Writer

// CommandTimeout bounds how long any single command may run before it is killed
// and reported as a timeout. This is what turns a silent hang (an unexpected
// apt/debconf prompt, a stuck lock) into a clear, recoverable error.
var CommandTimeout = 15 * time.Minute

var (
	activityMu sync.RWMutex
	activity   string
)

func setActivity(s string) {
	activityMu.Lock()
	activity = s
	activityMu.Unlock()
}

// Activity returns the most recent output line of the running command, for the
// runner to display live under the active step.
func Activity() string {
	activityMu.RLock()
	defer activityMu.RUnlock()
	return activity
}

// Attention is something the operator must do while a step waits — e.g. open
// a login link. The runner shows it prominently (with a QR code for URLs)
// until the step clears it.
type Attention struct {
	Title string
	URL   string
	Hint  string
}

var (
	attentionMu sync.RWMutex
	attention   *Attention
)

// SetAttention publishes (or, with nil, clears) the current operator action.
func SetAttention(a *Attention) {
	attentionMu.Lock()
	attention = a
	attentionMu.Unlock()
}

// CurrentAttention returns the pending operator action, or nil.
func CurrentAttention() *Attention {
	attentionMu.RLock()
	defer attentionMu.RUnlock()
	return attention
}

// Run executes a command, streaming its output to the log and live display, and
// returns the combined output.
func Run(name string, args ...string) (string, error) {
	return execute(name+" "+strings.Join(args, " "), name, args, "")
}

// RunRedacted executes name/args like Run but records logline in CommandLog
// instead of the real command line, so secrets passed as arguments never reach
// the log (dry-run output, tests, summaries).
func RunRedacted(logline, name string, args ...string) (string, error) {
	return execute(logline, name, args, "")
}

// RunWatch executes like RunRedacted (logline is what gets recorded) and calls
// onLine with every output line as it arrives — for commands that print
// something the operator must act on while they wait, such as a login URL.
func RunWatch(logline string, onLine func(string), name string, args ...string) (string, error) {
	return executeEnv(logline, name, args, "", nil, onLine)
}

// RunEnv executes like Run but with extra KEY=VALUE entries appended to the
// environment. The values never appear in CommandLog, so it is safe for
// secrets consumed via env (e.g. `docker run -e KEY` without a value).
func RunEnv(env []string, name string, args ...string) (string, error) {
	return executeEnv(name+" "+strings.Join(args, " "), name, args, "", env, nil)
}

// RunShell runs a command through `bash -c`, for pipelines and redirects.
func RunShell(script string) (string, error) {
	return execute(script, "bash", []string{"-c", script}, "")
}

// RunInput runs a command feeding the given string to its stdin (e.g. chpasswd).
// The stdin content is never logged, so it is safe for secrets.
func RunInput(stdin, name string, args ...string) error {
	_, err := execute(name+" "+strings.Join(args, " ")+" (stdin hidden)", name, args, stdin)
	return err
}

func execute(logline, name string, args []string, stdin string) (string, error) {
	return executeEnv(logline, name, args, stdin, nil, nil)
}

// executeEnv is execute with optional extra environment entries (never logged)
// and an optional per-line callback.
func executeEnv(logline, name string, args []string, stdin string, extraEnv []string, onLine func(string)) (string, error) {
	CommandLog = append(CommandLog, strings.TrimSpace(logline))
	if DryRun {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if LogWriter != nil {
		fmt.Fprintf(LogWriter, "\n$ %s\n", logline)
	}

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	var buf strings.Builder
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			buf.WriteString(line)
			buf.WriteByte('\n')
			setActivity(line)
			if onLine != nil {
				onLine(line)
			}
			if LogWriter != nil {
				fmt.Fprintln(LogWriter, line)
			}
		}
		close(done)
	}()

	runErr := cmd.Run()
	pw.Close()
	<-done
	setActivity("")

	if ctx.Err() == context.DeadlineExceeded {
		return buf.String(), fmt.Errorf("%s: timed out after %s — likely a stuck prompt or lock; see the log", logline, CommandTimeout)
	}
	if runErr != nil {
		return buf.String(), fmt.Errorf("%s: %w\n%s", logline, runErr, tail(buf.String(), 20))
	}
	return buf.String(), nil
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Output runs a read-only query command and returns its trimmed stdout. Like
// the other read-only helpers it runs even in dry-run and is not recorded in
// CommandLog — it must never be used for anything that changes the host.
func Output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
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

// RemoveFile deletes a file if it exists. Honours dry-run.
func RemoveFile(path string) error {
	CommandLog = append(CommandLog, "remove "+path)
	if DryRun {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
