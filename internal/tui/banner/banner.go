package banner

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var lines = [7]string{
	`   █     █  ▄▄▄▄▄▄  █     █  ▄▄▄▄▄▄  █     █  ▄▄▄▄▄▄  █▀▀▀▀▄  █▀▀▀▀▄ `,
	`   █     █ █      █ █▀▄   █ █        █     █ █      █ █    █ █    █ `,
	`    █   █  █▄▄▄▄▄▄█ █  ▀▄ █ █   ▀▀█  █     █ █▄▄▄▄▄▄█ █▄▄▄▄▀ █    █ `,
	`     █ █   █      █ █    ▀█ █     █  █     █ █      █ █   ▀▄ █    █ `,
	`      █    █      █ █     █  ▀▀▀▀▀▀   ▀▀▀▀▀  █      █ █    █ █▄▄▄▄▀ `,
	`                                                                    `,
	``,
}
var gradient = [6]string{
	"#BD93F9", // Lavender
	"#9B67FB", // Royal Purple
	"#7C4DFF", // Deep Purple
	"#536DFE", // Indigo
	"#448AFF", // Blue
	"#18FFFF", // Cyan
}

func Render(version string) string {
	var b strings.Builder

	for i, line := range lines[:6] {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradient[i]))
		b.WriteString(style.Render(line))
		b.WriteByte('\n')
	}
	displayVersion := version
	if len(displayVersion) > 0 && displayVersion[0] == 'v' {
		displayVersion = displayVersion[1:]
	}
	tagline := lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#9E9E9E"}).
		Italic(true).
		Render(fmt.Sprintf("  Security Vanguard v%s", displayVersion))

	b.WriteString(tagline)
	b.WriteByte('\n')

	return b.String()
}
func RenderCompact() string {
	v := lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Bold(true)
	a := lipgloss.NewStyle().Foreground(lipgloss.Color("#9B67FB")).Bold(true)
	n := lipgloss.NewStyle().Foreground(lipgloss.Color("#7C4DFF")).Bold(true)
	g := lipgloss.NewStyle().Foreground(lipgloss.Color("#536DFE")).Bold(true)
	u := lipgloss.NewStyle().Foreground(lipgloss.Color("#448AFF")).Bold(true)
	a2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#18FFFF")).Bold(true)
	r := lipgloss.NewStyle().Foreground(lipgloss.Color("#18FFFF")).Bold(true)
	d := lipgloss.NewStyle().Foreground(lipgloss.Color("#18FFFF")).Bold(true)

	return v.Render("V") + a.Render("A") + n.Render("N") + g.Render("G") + u.Render("U") + a2.Render("A") + r.Render("R") + d.Render("D")
}
func RenderWithBox(version string) string {
	inner := Render(version)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#5E35B1", Dark: "#7C4DFF"}).
		Padding(0, 2)

	return box.Render(inner)
}
func ShieldIcon() string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C4DFF")).
		Bold(true).
		Render("🛡")
}
