// Package ui renders the wizard, banner and execution runner.
package ui

import "github.com/charmbracelet/lipgloss"

// Palette — a warm "forge" theme: ember orange, steel, ash.
var (
	ColorEmber = lipgloss.Color("#FF6B35")
	ColorGold  = lipgloss.Color("#F7B538")
	ColorSteel = lipgloss.Color("#4ECDC4")
	ColorAsh   = lipgloss.Color("#8D99AE")
	ColorOK    = lipgloss.Color("#06D6A0")
	ColorErr   = lipgloss.Color("#EF476F")
	ColorMuted = lipgloss.Color("#6C757D")
)

var (
	StyleTitle = lipgloss.NewStyle().Foreground(ColorEmber).Bold(true)
	StyleSub   = lipgloss.NewStyle().Foreground(ColorAsh).Italic(true)
	StyleOK    = lipgloss.NewStyle().Foreground(ColorOK).Bold(true)
	StyleErr   = lipgloss.NewStyle().Foreground(ColorErr).Bold(true)
	StyleWarn  = lipgloss.NewStyle().Foreground(ColorGold).Bold(true)
	StyleMuted = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleKey   = lipgloss.NewStyle().Foreground(ColorSteel).Bold(true)

	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorEmber).
			Padding(0, 2)

	StyleWarnBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorGold).
			Padding(0, 2)
)

// Icons used in the runner output.
const (
	IconOK      = "✓"
	IconErr     = "✗"
	IconSkip    = "○"
	IconRunning = "▶"
)
