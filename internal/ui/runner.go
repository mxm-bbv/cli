package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

type status int

const (
	statusPending status = iota
	statusRunning
	statusOK
	statusSkip
	statusErr
)

type stepState struct {
	name    string
	status  status
	err     error
	started time.Time
	took    time.Duration
}

type stepDoneMsg struct {
	index  int
	status status
	err    error
}

// tickMsg refreshes elapsed times and the live output line.
type tickMsg struct{}

// RunnerModel drives sequential execution of the provisioning steps with a
// live output line, an action panel (e.g. a Tailscale login QR code) and a
// retry/skip/quit prompt when a step fails.
type RunnerModel struct {
	steps     []steps.Step
	ctx       *steps.Context
	states    []stepState
	spinner   spinner.Model
	current   int
	paused    bool // waiting for the user to decide on a failed step
	pausedAt  int
	quitArmed bool // ctrl+c pressed once while a step runs
	Failed    bool
	done      bool
	logPath   string
	started   time.Time
	width     int
	height    int
}

// NewRunner builds a runner model for the given steps and shared context.
func NewRunner(st []steps.Step, ctx *steps.Context, logPath string) RunnerModel {
	sp := spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(ColorEmber)),
	)
	now := time.Now()
	states := make([]stepState, len(st))
	for i, s := range st {
		states[i] = stepState{name: s.Name, status: statusPending}
	}
	if len(states) > 0 {
		states[0].status, states[0].started = statusRunning, now
	}
	return RunnerModel{steps: st, ctx: ctx, states: states, spinner: sp, logPath: logPath, started: now}
}

func (m RunnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runStep(0), tick())
}

func tick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m RunnerModel) runStep(i int) tea.Cmd {
	if i >= len(m.steps) {
		return nil
	}
	st := m.steps[i]
	ctx := m.ctx
	return func() tea.Msg {
		if st.Skip != nil && st.Skip(ctx) {
			return stepDoneMsg{index: i, status: statusSkip}
		}
		if err := st.Run(ctx); err != nil {
			return stepDoneMsg{index: i, status: statusErr, err: err}
		}
		return stepDoneMsg{index: i, status: statusOK}
	}
}

// start marks step i running and launches it, or finishes the run.
func (m RunnerModel) start(i int) (RunnerModel, tea.Cmd) {
	m.current = i
	if i >= len(m.steps) {
		m.done = true
		return m, tea.Quit
	}
	m.states[i].status, m.states[i].started, m.states[i].err = statusRunning, time.Now(), nil
	return m, m.runStep(i)
}

func (m RunnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tea.KeyPressMsg:
		key := strings.ToLower(msg.String())
		if m.paused {
			switch key {
			case "r": // retry the failed step
				m.paused = false
				return m.start(m.pausedAt)
			case "s": // skip and continue
				m.states[m.pausedAt].status = statusSkip
				m.paused = false
				return m.start(m.pausedAt + 1)
			case "q", "ctrl+c":
				m.Failed, m.done = true, true
				return m, tea.Quit
			}
			return m, nil
		}
		// A step is running: aborting may leave the box half-configured, so
		// ctrl+c must be pressed twice.
		if key == "ctrl+c" {
			if m.quitArmed {
				m.Failed, m.done = true, true
				return m, tea.Quit
			}
			m.quitArmed = true
			return m, nil
		}
		m.quitArmed = false

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		if m.done {
			return m, nil
		}
		return m, tick()

	case stepDoneMsg:
		s := &m.states[msg.index]
		s.status, s.err = msg.status, msg.err
		if msg.status != statusSkip {
			s.took = time.Since(s.started)
		}
		if msg.status == statusErr {
			// Pause and let the user decide instead of dying silently.
			m.paused, m.pausedAt = true, msg.index
			return m, nil
		}
		return m.start(msg.index + 1)
	}
	return m, nil
}

func (m RunnerModel) View() tea.View {
	return tea.NewView(m.render())
}

// render lays the runner out for the current terminal size. Every line is cut
// to the terminal width — a wrapped line would break the inline redraw.
func (m RunnerModel) render() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	var lines []string
	add := func(s ...string) {
		for _, l := range s {
			lines = append(lines, strings.Split(l, "\n")...)
		}
	}

	finished := 0
	for _, s := range m.states {
		if s.status == statusOK || s.status == statusSkip || s.status == statusErr {
			finished++
		}
	}
	total := len(m.states)
	add("", StyleTitle.Render("  Forging "+system.Hostname())+
		StyleMuted.Render(fmt.Sprintf("  ·  %d/%d steps  ·  %s", finished, total, clock(time.Since(m.started)))))
	add("  " + progressBar(finished, total, min(width-4, 48)))
	add("")

	attn := system.CurrentAttention()
	for i, s := range m.states {
		// While the operator has something to do, show only the step that is
		// waiting so the action panel fits on small terminals.
		if attn != nil && s.status != statusRunning {
			continue
		}
		add("  " + m.stepLine(s))
		if s.status == statusRunning && attn == nil {
			if act := cleanLine(system.Activity()); act != "" {
				add("       " + StyleMuted.Render(act))
			}
		}
		if m.paused && i == m.pausedAt {
			add(m.failurePanel(s, width))
		}
	}

	if attn != nil {
		used := len(lines) + 1
		add("", attentionPanel(attn, width, m.height-used))
		if left := total - finished - 1; left > 0 {
			add(StyleMuted.Render(fmt.Sprintf("  … %d more steps after this one", left)))
		}
	}
	if m.quitArmed {
		add("", StyleWarn.Render("  Press ctrl+c again to abort.")+
			StyleMuted.Render(" The current step keeps running in the background and may leave the server half-configured."))
	}
	add("")

	for i, l := range lines {
		lines[i] = ansi.Truncate(l, width, "…")
	}
	return strings.Join(lines, "\n")
}

func (m RunnerModel) stepLine(s stepState) string {
	switch s.status {
	case statusOK:
		return StyleOK.Render(IconOK) + "  " + s.name + "  " + StyleMuted.Render(dur(s.took))
	case statusSkip:
		return StyleMuted.Render(IconSkip + "  " + s.name + "  · skipped")
	case statusErr:
		return StyleErr.Render(IconErr+"  "+s.name) + "  " + StyleMuted.Render(dur(s.took))
	case statusRunning:
		// Dot frames carry their own trailing space.
		return m.spinner.View() + " " + StyleKey.Render(s.name) + "  " + StyleMuted.Render(dur(time.Since(s.started)))
	default:
		return StyleMuted.Render("·  " + s.name)
	}
}

// failurePanel shows the error (wrapped to the terminal) and the choices.
func (m RunnerModel) failurePanel(s stepState, width int) string {
	msg := "unknown error"
	if s.err != nil {
		msg = strings.TrimSpace(s.err.Error())
	}
	// The error carries the command's output tail; keep the panel readable
	// and point at the full log for the rest.
	if l := strings.Split(msg, "\n"); len(l) > 14 {
		msg = strings.Join(append(l[:2], append([]string{"…"}, l[len(l)-11:]...)...), "\n")
	}
	inner := max(width-10, 20)
	body := lipgloss.NewStyle().Width(inner).Render(cleanBlock(msg))
	keys := StyleWarn.Render("[r]") + " retry   " + StyleWarn.Render("[s]") + " skip   " + StyleWarn.Render("[q]") + " quit"
	if m.logPath != "" {
		keys += StyleMuted.Render("   full log: " + m.logPath)
	}
	return lipgloss.NewStyle().MarginLeft(4).Render(
		StyleErrBox.Render(StyleErr.Render("Step failed") + "\n\n" + body + "\n\n" + keys))
}

// attentionPanel renders an operator action: title, QR code (when there is
// room), the link — clickable in terminals that support OSC 8 — and a hint.
func attentionPanel(a *system.Attention, width, rows int) string {
	parts := []string{StyleWarn.Render("▶  " + a.Title)}
	if a.URL != "" {
		qr := QRCode(a.URL)
		qrRows, qrCols := strings.Count(qr, "\n")+1, ansi.StringWidth(strings.SplitN(qr, "\n", 2)[0])
		// rows <= 0: terminal size unknown — show it rather than hide it.
		extra := 9
		if a.Code != "" {
			extra += 2
		}
		fits := qr != "" && qrCols+8 <= width && (rows <= 0 || qrRows+extra <= rows)
		if fits {
			parts = append(parts, "", qr)
		}
		parts = append(parts, "", StyleKey.Hyperlink(a.URL).Render(a.URL))
		if !fits && qr != "" {
			parts = append(parts, StyleMuted.Render("(enlarge the terminal to get a QR code for your phone)"))
		}
	}
	if a.Code != "" {
		code := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).
			Background(ColorGold).Padding(0, 1).Render(a.Code)
		parts = append(parts, "", StyleKey.Render("Code: ")+code)
	}
	if a.Hint != "" {
		parts = append(parts, "", StyleMuted.Width(min(max(width-12, 20), 70)).Render(a.Hint))
	}
	return lipgloss.NewStyle().MarginLeft(2).Render(StyleWarnBox.Render(strings.Join(parts, "\n")))
}

// progressBar draws a fixed-width bar for done/total.
func progressBar(done, total, width int) string {
	if width < 10 || total == 0 {
		return ""
	}
	filled := width * done / total
	return lipgloss.NewStyle().Foreground(ColorEmber).Render(strings.Repeat("━", filled)) +
		StyleMuted.Render(strings.Repeat("─", width-filled))
}

// cleanLine makes a raw command output line safe to show on one terminal row:
// no escape sequences, no carriage-return progress redraws, no tabs or other
// control characters.
func cleanLine(s string) string {
	s = ansi.Strip(s)
	if i := strings.LastIndex(s, "\r"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s))
}

// cleanBlock applies cleanLine to every line of a multi-line text.
func cleanBlock(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = cleanLine(l)
	}
	return strings.Join(lines, "\n")
}

// dur formats a step duration compactly: 850ms → "<1s", 75s → "1m15s".
func dur(d time.Duration) string {
	switch {
	case d < time.Second:
		return "<1s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	default:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

// clock formats the total elapsed time as mm:ss.
func clock(d time.Duration) string {
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

// Summary renders the post-run report (printed by main after the program exits).
func Summary(ctx *steps.Context, dryRun bool, logPath string) string {
	cfg := ctx.Cfg
	var b strings.Builder

	title := "  Server forged successfully  "
	if dryRun {
		title = "  Dry run complete — nothing was changed  "
	}
	b.WriteString(StyleOK.Render(title) + "\n\n")

	rows := []string{
		fmt.Sprintf("%s  %s", StyleKey.Render("Host IP:"), system.PrimaryIP()),
		fmt.Sprintf("%s  %s", StyleKey.Render("Deploy user:"), cfg.Username),
		fmt.Sprintf("%s  %d", StyleKey.Render("SSH port:"), portOrDefault(cfg.SSHPort)),
		fmt.Sprintf("%s  root login %s, password auth %s", StyleKey.Render("SSH access:"),
			onOff(!cfg.DisableRootLogin), onOff(!cfg.DisablePassauth)),
	}
	if cfg.InstallPortainer {
		if ctx.AgentDeferred {
			rows = append(rows, fmt.Sprintf("%s  %s", StyleKey.Render("Portainer Agent:"),
				StyleWarn.Render("starts after Tailscale login —  sudo forge tailscale")))
		} else if cfg.PortainerAccess == config.PortainerTailnet {
			rows = append(rows, fmt.Sprintf("%s  %s:9001 %s", StyleKey.Render("Portainer Agent:"),
				ctx.TailnetIP, StyleOK.Render("(tailnet only — invisible to the internet)")))
		} else {
			rows = append(rows, fmt.Sprintf("%s  %s:9001 %s", StyleKey.Render("Portainer Agent:"),
				system.PrimaryIP(), StyleWarn.Render("(PUBLIC — protected only by AGENT_SECRET)")))
		}
	}
	b.WriteString(StyleBox.Render(strings.Join(rows, "\n")) + "\n")

	writeArtifacts(&b, ctx)

	if !dryRun && (cfg.DisableRootLogin || cfg.DisablePassauth) {
		warn := strings.Join([]string{
			StyleWarn.Render("⚠  BEFORE CLOSING THIS SESSION"),
			"Open a NEW terminal and confirm you can log in:",
			StyleKey.Render(fmt.Sprintf("    ssh -p %d %s@%s", portOrDefault(cfg.SSHPort), cfg.Username, system.PrimaryIP())),
			"Root login and/or password auth are now disabled — if the key",
			"doesn't work, fix it from THIS still-open session.",
		}, "\n")
		b.WriteString("\n" + StyleWarnBox.Render(warn) + "\n")
	}

	if logPath != "" {
		b.WriteString("\n" + StyleMuted.Render("  Full log: "+logPath) + "\n")
	}
	return b.String()
}

// Report renders the short report of a follow-up command (`forge tailscale`,
// `forge github`): what it produced and the notes, without the host overview.
func Report(title string, ctx *steps.Context, logPath string) string {
	var b strings.Builder
	b.WriteString(StyleOK.Render("  "+title+"  ") + "\n")
	if ctx.TailnetIP != "" {
		b.WriteString("\n" + StyleKey.Render("  Tailnet IP: ") + ctx.TailnetIP + "\n")
		if ctx.AgentSecret != "" {
			b.WriteString(StyleKey.Render("  Portainer Agent: ") + ctx.TailnetIP + ":9001\n")
		}
	}
	writeArtifacts(&b, ctx)
	if logPath != "" {
		b.WriteString("\n" + StyleMuted.Render("  Full log: "+logPath) + "\n")
	}
	return b.String()
}

// writeArtifacts appends the one-time values a run produced and its notes.
func writeArtifacts(b *strings.Builder, ctx *steps.Context) {
	if ctx.AgentSecret != "" {
		b.WriteString("\n" + StyleTitle.Render("  Portainer AGENT_SECRET") +
			StyleMuted.Render("  — enter it when adding this endpoint in Portainer (shown only once):") + "\n")
		b.WriteString(StyleBox.Render(ctx.AgentSecret) + "\n")
	}

	if ctx.GitHubPubKey != "" {
		b.WriteString("\n" + StyleTitle.Render("  GitHub deploy key") +
			StyleMuted.Render("  — add to repo → Settings → Deploy keys:") + "\n")
		b.WriteString(StyleBox.Render(ctx.GitHubPubKey) + "\n")
	}

	if len(ctx.Notes) > 0 {
		b.WriteString("\n" + StyleKey.Render("  Notes:") + "\n")
		width := 100
		if w, _, err := term.GetSize(os.Stdout.Fd()); err == nil && w > 0 {
			width = min(w, 100)
		}
		for _, n := range ctx.Notes {
			// Wrap at word boundaries, continuation lines under the text.
			wrapped := ansi.Wordwrap(n, max(width-7, 30), "")
			b.WriteString("    • " + strings.ReplaceAll(wrapped, "\n", "\n      ") + "\n")
		}
	}
}

func portOrDefault(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func onOff(b bool) string {
	if b {
		return StyleWarn.Render("ON")
	}
	return StyleOK.Render("OFF")
}
