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

// stepDoneMsg is emitted after a step finishes.
type stepDoneMsg struct {
	index  int
	status status
	err    error
}

// RunnerModel drives sequential execution of the provisioning steps.
type RunnerModel struct {
	steps   []steps.Step
	ctx     *steps.Context
	states  []stepState
	spinner spinner.Model
	current int
	Failed  bool
	done    bool
}

// NewRunner builds a runner model for the given steps and shared context.
func NewRunner(st []steps.Step, ctx *steps.Context) RunnerModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(ColorEmber)

	states := make([]stepState, len(st))
	for i, s := range st {
		states[i] = stepState{name: s.Name, status: statusPending}
	}
	return RunnerModel{steps: st, ctx: ctx, states: states, spinner: sp, current: 0}
}

func (m RunnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runStep(0))
}

// runStep returns a command that executes step i in the background.
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
		if msg.Type == tea.KeyCtrlC {
			m.Failed = true
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
			m.Failed = true
			m.done = true
			return m, tea.Quit
		}
		next := msg.index + 1
		m.current = next
		if next >= len(m.steps) {
			m.done = true
			return m, tea.Quit
		}
		return m, m.runStep(next)
	}
	// keep the spinner ticking
	if !m.done {
		m.states[clamp(m.current, len(m.states))].status = statusRunning
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
			icon = StyleOK.Render(IconOK)
			name = s.name
		case statusSkip:
			icon = StyleMuted.Render(IconSkip)
			name = StyleMuted.Render(s.name + "  (already done / disabled)")
		case statusErr:
			icon = StyleErr.Render(IconErr)
			name = StyleErr.Render(s.name)
		case statusRunning:
			icon = m.spinner.View()
			name = StyleKey.Render(s.name)
		default:
			icon = StyleMuted.Render("·")
			name = StyleMuted.Render(s.name)
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", icon, name))
	}

	if m.done {
		b.WriteString("\n")
		if m.Failed {
			for _, s := range m.states {
				if s.status == statusErr && s.err != nil {
					b.WriteString(StyleErr.Render("  ✗ "+s.name) + "\n")
					b.WriteString(StyleMuted.Render(indent(s.err.Error())) + "\n")
				}
			}
		}
	}
	return b.String()
}

func clamp(i, n int) int {
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = "      " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// Summary renders the post-run report (printed by main after the program exits).
func Summary(ctx *steps.Context, dryRun bool) string {
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
			StyleMuted.Render("  — add this to repo → Settings → Deploy keys:") + "\n")
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
