package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Brand and Platform fill the wizard's header line ("◆ forge v1.2.3" on the
// left, the detected OS on the right). main sets them before the first form.
var (
	Brand    = "forge"
	Platform = ""
)

// page is one screen of a wizard: a title for the header and its fields.
// hide, if set, skips the page while it returns true.
type page struct {
	title  string
	fields []huh.Field
	hide   func() bool
}

// wizard runs huh pages full-screen, on the terminal's alternate screen.
//
// Inline (in the scrollback) a huh form is as tall as its tallest page and is
// redrawn by moving the cursor up that many lines. Terminals disagree about
// where such a move lands once the frame meets the bottom of the window —
// in some (IDE terminals among them) the whole form slides up a line and the
// focused field's title disappears. The alternate screen is addressed by
// absolute positions, so every line lands where it is meant to.
type wizard struct {
	form          *huh.Form
	pages         []page
	index         map[huh.Field]int // field → its page
	cur           int               // page of the focused field
	width, height int
}

// Rows the header and margins take: blank, brand, progress, blank, title,
// blank — and a blank at the bottom.
const wizardChrome = 7

func runPages(pages ...page) error {
	w := newWizard(pages...)
	final, err := tea.NewProgram(w).Run()
	if err != nil {
		return fmt.Errorf("wizard: %w", err)
	}
	if final.(wizard).form.State != huh.StateCompleted {
		return huh.ErrUserAborted
	}
	return nil
}

func newWizard(pages ...page) wizard {
	groups := make([]*huh.Group, 0, len(pages))
	index := map[huh.Field]int{}
	for i, p := range pages {
		g := huh.NewGroup(p.fields...)
		if p.hide != nil {
			g = g.WithHideFunc(p.hide)
		}
		groups = append(groups, g)
		for _, f := range p.fields {
			index[f] = i
		}
	}
	form := huh.NewForm(groups...).WithTheme(forgeTheme()).WithShowErrors(true)
	return wizard{form: form, pages: pages, index: index}
}

func (w wizard) Init() tea.Cmd { return w.form.Init() }

func (w wizard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		w.width, w.height = ws.Width, ws.Height
		// The form gets the column and the rows below the header. Its view
		// is one line taller than the height it is given (the blank line
		// above the help), hence the extra 1.
		msg = tea.WindowSizeMsg{Width: w.columnWidth(), Height: max(w.height-wizardChrome-1, 4)}
	}
	m, cmd := w.form.Update(msg)
	w.form = m.(*huh.Form)
	if i, ok := w.index[w.form.GetFocusedField()]; ok {
		w.cur = i
	}
	if w.form.State != huh.StateNormal {
		return w, tea.Quit
	}
	return w, cmd
}

func (w wizard) View() tea.View {
	v := tea.NewView(w.render())
	v.AltScreen = true
	return v
}

// columnWidth: the form column — never the full width, so nothing is drawn
// in the last column (where some terminals wrap or scroll early).
func (w wizard) columnWidth() int {
	if w.width <= 0 {
		return 76
	}
	return max(min(w.width-4, 84), 20)
}

// step returns the focused page's position among the pages shown.
func (w wizard) step() (n, total int) {
	for i, p := range w.pages {
		if p.hide != nil && p.hide() {
			continue
		}
		total++
		if i <= w.cur {
			n = total
		}
	}
	return n, total
}

func (w wizard) render() string {
	if w.form.State != huh.StateNormal {
		return ""
	}
	col := w.columnWidth()
	n, total := w.step()

	brand := StyleTitle.Render("◆ "+Brand) + StyleMuted.Render("  ·  server setup")
	right := StyleMuted.Render(Platform)
	gap := col - lipgloss.Width(brand) - lipgloss.Width(right)
	if gap < 2 {
		right, gap = "", col-lipgloss.Width(brand)
	}
	header := brand + strings.Repeat(" ", max(gap, 0)) + right

	count := fmt.Sprintf("  %d / %d", n, total)
	progress := progressBar(n, total, col-len(count)) + StyleMuted.Render(count)

	title := ""
	if w.cur < len(w.pages) {
		title = StyleTitle.Render(w.pages[w.cur].title)
	}

	lines := []string{"", header, progress, "", title, ""}
	lines = append(lines, strings.Split(w.form.View(), "\n")...)
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, col, "…")
	}

	// Center the column on wide terminals, a two-column margin otherwise.
	left := 2
	if w.width > col+8 {
		left = (w.width - col) / 2
	}
	return lipgloss.NewStyle().MarginLeft(left).Render(strings.Join(lines, "\n"))
}
