package components

import (
	"github.com/haliminurja/vanguard/internal/tui/theme"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/lipgloss"
)

func RenderFooter(helpModel help.Model, keys help.KeyMap, t *theme.Theme, width int) string {
	helpView := helpModel.View(keys)

	signature := t.Muted.Render(" VANGUARD SENTINEL ")
	sigWidth := lipgloss.Width(signature)
	helpWidth := lipgloss.Width(helpView)

	gap := width - helpWidth - sigWidth - 2
	if gap < 0 {
		gap = 1
	}
	padding := repeat(" ", gap)

	footer := lipgloss.JoinHorizontal(lipgloss.Center, helpView, padding, signature)
	return t.FooterBar.Width(width).Render(footer)
}
func RenderSeparator(t *theme.Theme, width int) string {
	line := lipgloss.NewStyle().
		Foreground(t.Colors.Border).
		Render(repeat("─", width))
	return line
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	result := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		result = append(result, s...)
	}
	return string(result)
}
