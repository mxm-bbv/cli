package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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
	name   string
	status status
	err    error
}

type stepDoneMsg struct {
	index  int
	status status
	err    error
}

// RunnerModel drives sequential execution of the provisioning steps, with a
// live output line, and a retry/skip/abort prompt when a step fails.
type RunnerModel struct {
	steps    []steps.Step
	ctx      *steps.Context
	states   []stepState
	spinner  spinner.Model
	current  int
	paused   bool // waiting for the user to decide on a failed step
	pausedAt int
	Failed   bool
	done     bool
	logPath  string
}

// NewRunner builds a runner model for the given steps and shared context.
func NewRunner(st []steps.Step, ctx *steps.Context, logPath string) RunnerModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(ColorEmber)

	states := make([]stepState, len(st))
	for i, s := range st {
		states[i] = stepState{name: s.Name, status: statusPending}
	}
	return RunnerModel{steps: st, ctx: ctx, states: states, spinner: sp, logPath: logPath}
}

func (m RunnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runStep(0))
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

func (m RunnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.paused {
			switch strings.ToLower(msg.String()) {
			case "r": // retry the failed step
				m.states[m.pausedAt] = stepState{name: m.states[m.pausedAt].name, status: statusRunning}
				m.paused = false
				m.current = m.pausedAt
				return m, m.runStep(m.pausedAt)
			case "s": // skip and continue
				m.states[m.pausedAt].status = statusSkip
				m.paused = false
				next := m.pausedAt + 1
				m.current = next
				if next >= len(m.steps) {
					m.done = true
					return m, tea.Quit
				}
				return m, m.runStep(next)
			case "q", "ctrl+c":
				m.Failed = true
				m.done = true
				return m, tea.Quit
			}
			return m, nil
		}
		if msg.Type == tea.KeyCtrlC {
			m.Failed = true
			m.done = true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case stepDoneMsg:
		m.states[msg.index].status = msg.status
		m.states[msg.index].err = msg.err
		if msg.status == statusErr {
			// Pause and let the user decide instead of dying silently.
			m.paused = true
			m.pausedAt = msg.index
			return m, nil
		}
		next := msg.index + 1
		m.current = next
		if next >= len(m.steps) {
			m.done = true
			return m, tea.Quit
		}
		m.states[next].status = statusRunning
		return m, m.runStep(next)
	}
	if !m.done && !m.paused && m.current < len(m.states) {
		m.states[m.current].status = statusRunning
	}
	return m, nil
}

func (m RunnerModel) View() string {
	var b strings.Builder
	b.WriteString(StyleTitle.Render("  Forging your server…") + "\n\n")

	for _, s := range m.states {
		var icon, name string
		switch s.status {
		case statusOK:
			icon, name = StyleOK.Render(IconOK), s.name
		case statusSkip:
			icon = StyleMuted.Render(IconSkip)
			name = StyleMuted.Render(s.name + "  (already done / skipped)")
		case statusErr:
			icon, name = StyleErr.Render(IconErr), StyleErr.Render(s.name)
		case statusRunning:
			icon, name = m.spinner.View(), StyleKey.Render(s.name)
		default:
			icon, name = StyleMuted.Render("·"), StyleMuted.Render(s.name)
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", icon, name))

		if s.status == statusRunning {
			if act := system.Activity(); act != "" {
				b.WriteString("       " + StyleMuted.Render(truncate(act, 76)) + "\n")
			}
		}
	}

	if m.paused {
		b.WriteString("\n" + StyleErr.Render("  ✗ "+m.states[m.pausedAt].name+" failed:") + "\n")
		if e := m.states[m.pausedAt].err; e != nil {
			b.WriteString(StyleMuted.Render(indent(e.Error())) + "\n")
		}
		b.WriteString("\n  " + StyleWarn.Render("[r]") + " retry   " +
			StyleWarn.Render("[s]") + " skip   " +
			StyleWarn.Render("[q]") + " quit    " +
			StyleMuted.Render("(full log: "+m.logPath+")") + "\n")
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = "      " + lines[i]
	}
	return strings.Join(lines, "\n")
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
		rows = append(rows, fmt.Sprintf("%s  %s:9001", StyleKey.Render("Portainer Agent:"), system.PrimaryIP()))
	}
	b.WriteString(StyleBox.Render(strings.Join(rows, "\n")) + "\n")

	if ctx.GitHubPubKey != "" {
		b.WriteString("\n" + StyleTitle.Render("  GitHub deploy key") +
			StyleMuted.Render("  — add to repo → Settings → Deploy keys:") + "\n")
		b.WriteString(StyleBox.Render(ctx.GitHubPubKey) + "\n")
	}

	if len(ctx.Notes) > 0 {
		b.WriteString("\n" + StyleKey.Render("  Notes:") + "\n")
		for _, n := range ctx.Notes {
			b.WriteString("    • " + n + "\n")
		}
	}

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
