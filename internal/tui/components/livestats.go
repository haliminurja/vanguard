package components

import (
	"fmt"
	"strings"

	"vanguard/internal/models"
	"vanguard/internal/tui/theme"

	"github.com/charmbracelet/lipgloss"
)

func RenderLiveStats(counts map[models.Severity]int, t *theme.Theme, width int) string {
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	var badges []string
	for _, sev := range severities {
		count := counts[sev]
		style := t.SeverityStyles[sev]
		badge := style.Render(fmt.Sprintf(" %s: %d ", sev.String(), count))
		badges = append(badges, badge)
	}

	separator := t.Muted.Render("  ")
	row := strings.Join(badges, separator)

	return lipgloss.PlaceHorizontal(width, lipgloss.Center, row)
}
func RenderTotalFindings(total int, t *theme.Theme) string {
	return t.Bold.Render(fmt.Sprintf("%d findings", total))
}
