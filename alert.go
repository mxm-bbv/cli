package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/alerts"
)

// runAlert is `forge alert`: forge's own scripts talking to Telegram, not a
// command for people (they set alerts up with the wizard or the alerts module).
//
//	forge alert send [--urgent] [--key K --every 6h] MESSAGE   (or the message on stdin)
//	forge alert login     an sshd login: pam_exec's PAM_USER and PAM_RHOST
//	forge alert digest    the daily summary, when it's due
func runAlert(args []string) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "forge alert is for forge's own scripts (root)")
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: forge alert send|login|digest")
		return 2
	}
	var err error
	switch args[0] {
	case "send":
		var a alerts.Alert
		if a, err = parseAlert(args[1:], os.Stdin); err == nil {
			err = alerts.Send(a)
		}
	case "login":
		err = alerts.Login(os.Getenv("PAM_USER"), os.Getenv("PAM_RHOST"))
	case "digest":
		err = alerts.Digest()
	default:
		fmt.Fprintln(os.Stderr, "usage: forge alert send|login|digest")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "forge alert:", err)
		return 1
	}
	return 0
}

// parseAlert reads `send`'s flags; the message is the rest of the arguments,
// or stdin when there are none.
func parseAlert(args []string, stdin io.Reader) (alerts.Alert, error) {
	var a alerts.Alert
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch args[0] {
		case "--urgent":
			a.Urgent = true
			args = args[1:]
			continue
		case "--key", "--every":
			if len(args) < 2 {
				return a, fmt.Errorf("%s needs a value", args[0])
			}
			if args[0] == "--key" {
				a.Key = args[1]
			} else {
				d, err := time.ParseDuration(args[1])
				if err != nil || d <= 0 {
					return a, fmt.Errorf("--every %q: a duration like 6h", args[1])
				}
				a.Every = d
			}
			args = args[2:]
		default:
			return a, fmt.Errorf("unknown flag %s", args[0])
		}
	}
	if a.Key != "" && a.Every == 0 {
		return a, fmt.Errorf("--key needs --every")
	}
	a.Text = strings.Join(args, " ")
	if a.Text == "" {
		body, err := io.ReadAll(io.LimitReader(stdin, 16<<10))
		if err != nil {
			return a, err
		}
		a.Text = strings.TrimSpace(string(body))
	}
	if a.Text == "" {
		return a, fmt.Errorf("nothing to send")
	}
	return a, nil
}
