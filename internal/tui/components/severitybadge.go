package components

import (
	"strings"

	"github.com/haliminurja/vanguard/internal/models"
	"github.com/haliminurja/vanguard/internal/tui/theme"
)

func RenderSeverityBadge(sev models.Severity, t *theme.Theme) string {
	style, ok := t.SeverityStyles[sev]
	if !ok {
		return sev.String()
	}
	return style.Render(strings.ToUpper(sev.String()))
}
