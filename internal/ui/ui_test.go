package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"rsc.io/qr"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

// TestQRCodeRoundTrip decodes the half-block rendering back into modules and
// compares it with the encoder's bitmap — a wrong glyph or an off-by-one row
// would make the code unscannable.
func TestQRCodeRoundTrip(t *testing.T) {
	const url = "https://login.tailscale.com/a/1a2b3c4d5e6f"
	code, err := qr.Encode(url, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(ansi.Strip(QRCode(url)), "\n")
	n := code.Size + 2*qrQuiet
	if len(rows) != (n+1)/2 {
		t.Fatalf("got %d rows, want %d", len(rows), (n+1)/2)
	}
	for ry, row := range rows {
		cells := []rune(row)
		if len(cells) != n {
			t.Fatalf("row %d is %d wide, want %d", ry, len(cells), n)
		}
		for x, r := range cells {
			top := r == '█' || r == '▀'
			bottom := r == '█' || r == '▄'
			if top != code.Black(x-qrQuiet, 2*ry-qrQuiet) || bottom != code.Black(x-qrQuiet, 2*ry+1-qrQuiet) {
				t.Fatalf("module mismatch at x=%d row=%d (%q)", x, ry, r)
			}
		}
	}
}

func TestCleanLine(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[32mok\x1b[0m":              "ok",
		"Progress 10%\rProgress 100%":    "Progress 100%",
		"\tindented\tline ":              "indented line",
		"bell\a and \x00 nul":            "bell and  nul",
		"Unpacking libc6 (2.39-0ubuntu)": "Unpacking libc6 (2.39-0ubuntu)",
	} {
		if got := cleanLine(in); got != want {
			t.Errorf("cleanLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRunnerFitsTerminal renders the runner in its busiest states and checks
// that no line is wider than the terminal: a wrapped line breaks the inline
// redraw (the "TUI garbage" symptom over narrow SSH sessions).
func TestRunnerFitsTerminal(t *testing.T) {
	st, ctx := steps.BuildSteps(config.Default())
	t.Cleanup(func() { system.SetAttention(nil) })

	for _, width := range []int{40, 60, 80, 120} {
		m := NewRunner(st, ctx, "/var/log/forge.log")
		next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 50})
		m = next.(RunnerModel)
		m.states[0].status, m.states[0].took = statusOK, 3*time.Second
		m.states[1].status, m.states[1].started = statusRunning, time.Now()
		m.current = 1

		check := func(state string) {
			t.Helper()
			for i, l := range strings.Split(m.render(), "\n") {
				if w := ansi.StringWidth(l); w > width {
					t.Errorf("width %d, %s: line %d is %d columns: %q", width, state, i, w, ansi.Strip(l))
				}
			}
		}
		check("running")

		system.SetAttention(&system.Attention{
			Title: "Add this server to your Tailscale network",
			URL:   "https://login.tailscale.com/a/1a2b3c4d5e6f",
			Hint:  "Scan the QR code with your phone (or open the link), sign in and approve. forge continues by itself.",
		})
		check("waiting for login")
		if width >= 80 && !strings.Contains(m.render(), "▀") {
			t.Errorf("width %d: QR code expected when it fits", width)
		}
		system.SetAttention(nil)

		long := "apt-get install -y docker-ce: exit status 100\n" + strings.Repeat("E: Unable to locate package docker-ce-really-long-name-that-goes-on\n", 30)
		m.states[1].status, m.states[1].err = statusErr, errors.New(long)
		m.paused, m.pausedAt = true, 1
		check("failed")
		if !strings.Contains(m.render(), "[r]") {
			t.Errorf("width %d: retry/skip/quit keys missing", width)
		}
	}
}

func TestDoubleCtrlCToAbort(t *testing.T) {
	st, ctx := steps.BuildSteps(config.Default())
	m := NewRunner(st, ctx, "")
	ctrlC := tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}

	next, cmd := m.Update(ctrlC)
	m = next.(RunnerModel)
	if m.Failed || cmd != nil || !m.quitArmed {
		t.Fatal("first ctrl+c must only arm the abort")
	}
	next, cmd = m.Update(ctrlC)
	m = next.(RunnerModel)
	if !m.Failed || cmd == nil {
		t.Fatal("second ctrl+c must abort")
	}
}

// TestFormFitsShortTerminal: when a later group is taller than the terminal,
// huh sizes every group to the terminal height and renders one line more, so
// the focused field's title scrolled out of sight. The form must fit, title
// included.
func TestFormFitsShortTerminal(t *testing.T) {
	for _, h := range []int{12, 16, 20} {
		var a, b string
		var c [8]bool
		tall := make([]huh.Field, len(c))
		for i := range c {
			tall[i] = huh.NewConfirm().Title("Question?").Value(&c[i])
		}
		f := newForm(
			huh.NewGroup(
				huh.NewInput().Title("Password for the deploy user").Value(&a),
				huh.NewInput().Title("Confirm password").Value(&b),
			),
			huh.NewGroup(tall...),
		)
		f.Init()
		f.Update(fitHeight(nil, tea.WindowSizeMsg{Width: 80, Height: h}))
		view := f.View()
		if got := lipgloss.Height(view); got > h {
			t.Errorf("height %d: form renders %d lines", h, got)
		}
		if !strings.Contains(view, "Password for the deploy user") {
			t.Errorf("height %d: focused field's title is missing:\n%s", h, view)
		}
	}
}
