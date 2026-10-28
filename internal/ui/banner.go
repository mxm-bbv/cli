package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

const asciiArt = `
 ██████╗██╗     ██╗
██╔════╝██║     ██║
██║     ██║     ██║
██║     ██║     ██║
╚██████╗███████╗██║
 ╚═════╝╚══════╝╚═╝
`

// Banner returns the styled ASCII banner with author credit, version and subtitle.
func Banner(version string) string {
	art := lipgloss.NewStyle().Foreground(ColorEmber).Bold(true).Render(asciiArt)
	credit := StyleKey.Render("  Created by mxm_bbv")
	subtitle := StyleSub.Render("  Forge a clean server into a production-ready host — Docker · Portainer · SSH · hardening")
	ver := StyleMuted.Render(fmt.Sprintf("  v%s", version))
	return strings.Join([]string{art, credit, subtitle, ver, ""}, "\n")
}
