package components

import (
	"strings"

	"vanguard/internal/models"
	"vanguard/internal/tui/theme"
)

func RenderSeverityBadge(sev models.Severity, t *theme.Theme) string {
	style, ok := t.SeverityStyles[sev]
	if !ok {
		return sev.String()
	}
	return style.Render(strings.ToUpper(sev.String()))
}
