package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const asciiArt = `
   ____                          ____
  / __/__ _____  _____ ____     / __/__  _______ ____
 _\ \/ -_) __/ |/ / -_) __/    / _// _ \/ __/ _ ` + "`" + `/ -_)
/___/\__/_/  |___/\__/_/      /_/  \___/_/  \_, /\__/
                                           /___/
`

// Banner returns the styled ASCII banner with version and subtitle.
func Banner(version string) string {
	art := lipgloss.NewStyle().Foreground(ColorEmber).Bold(true).Render(asciiArt)
	subtitle := StyleSub.Render("  Forge a clean server into a production-ready host — Docker · Portainer · SSH · hardening")
	ver := StyleMuted.Render(fmt.Sprintf("  v%s", version))
	return strings.Join([]string{art, subtitle, ver, ""}, "\n")
}
