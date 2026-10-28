package ui

import (
	"strings"

	"charm.land/lipgloss/v2"
	"rsc.io/qr"
)

// qrQuiet is the white margin around the code, in modules. The spec asks for
// four; two scans fine on phones and saves terminal rows.
const qrQuiet = 2

// QRCode renders text as a QR code with half-block characters (two modules per
// terminal row), dark on an explicit white background so it scans on dark and
// light terminals alike. It returns "" if the text can't be encoded.
func QRCode(text string) string {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return ""
	}
	n := code.Size + 2*qrQuiet
	dark := func(x, y int) bool { return code.Black(x-qrQuiet, y-qrQuiet) }
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(lipgloss.Color("#FFFFFF"))

	rows := make([]string, 0, (n+1)/2)
	for y := 0; y < n; y += 2 {
		var row strings.Builder
		for x := 0; x < n; x++ {
			switch top, bottom := dark(x, y), dark(x, y+1); {
			case top && bottom:
				row.WriteString("█")
			case top:
				row.WriteString("▀")
			case bottom:
				row.WriteString("▄")
			default:
				row.WriteString(" ")
			}
		}
		rows = append(rows, style.Render(row.String()))
	}
	return strings.Join(rows, "\n")
}
