package components

import (
	"fmt"
	"strings"

	"vanguard/internal/models"
	"vanguard/internal/tui/theme"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type FindingDetail struct {
	viewport viewport.Model
	finding  *models.Finding
	theme    *theme.Theme
	width    int
	height   int
}

func NewFindingDetail(t *theme.Theme) *FindingDetail {
	vp := viewport.New(60, 20)
	return &FindingDetail{viewport: vp, theme: t}
}
func (d *FindingDetail) SetFinding(f *models.Finding) {
	d.finding = f
	d.rebuildContent()
}
func (d *FindingDetail) SetSize(w, h int) {
	d.width = w
	d.height = h
	d.viewport.Width = w - 4
	d.viewport.Height = h - 4
	d.rebuildContent()
}
func (d *FindingDetail) HandleKey(msg tea.KeyMsg) {
	d.viewport, _ = d.viewport.Update(msg)
}

func (d *FindingDetail) rebuildContent() {
	if d.finding == nil {
		d.viewport.SetContent(d.theme.Muted.Render("  Select a finding to view details."))
		return
	}
	f := d.finding

	contentWidth := d.viewport.Width - 2
	if contentWidth < 20 {
		contentWidth = 20
	}

	sections := []string{
		lipgloss.JoinHorizontal(lipgloss.Top,
			RenderSeverityBadge(f.Severity, d.theme),
			"  ",
			d.theme.Title.Render(f.Title),
		),
		"",
		d.theme.Muted.Render(fmt.Sprintf("  Category: %s  |  Scanner: %s", f.Category, f.Scanner)),
		"",
	}
	if f.Description != "" {
		sections = append(sections,
			d.theme.Subtitle.Render("  Description"),
			wordWrap(f.Description, contentWidth),
			"",
		)
	}
	if f.File != "" {
		location := fmt.Sprintf("  %s:%d", f.File, f.Line)
		sections = append(sections,
			d.theme.Subtitle.Render("  Location"),
			d.theme.AccentStyle.Render(location),
			"",
		)
	}
	if f.CodeSnippet != "" {
		sections = append(sections, d.theme.Subtitle.Render("  Code Context"))
		lineNumStyle := d.theme.Muted.Copy().Width(4).Align(lipgloss.Right)

		startLine := f.Line - len(f.ContextBefore)
		for i, line := range f.ContextBefore {
			ln := lineNumStyle.Render(fmt.Sprintf("%d", startLine+i))
			sections = append(sections, "  "+ln+"  "+d.theme.Muted.Render(line))
		}

		ln := lineNumStyle.Foreground(d.theme.Colors.Accent).Bold(true).Render(fmt.Sprintf("%d", f.Line))
		hitLine := lipgloss.NewStyle().Foreground(d.theme.Colors.Low).Render(f.CodeSnippet)
		sections = append(sections, "  "+ln+"  "+hitLine)

		for i, line := range f.ContextAfter {
			ln := lineNumStyle.Render(fmt.Sprintf("%d", f.Line+i+1))
			sections = append(sections, "  "+ln+"  "+d.theme.Muted.Render(line))
		}
		sections = append(sections, "")
	}
	if f.Remediation != "" {
		sections = append(sections,
			d.theme.Subtitle.Render("  Remediation"),
			wordWrap(f.Remediation, contentWidth),
			"",
		)
	}
	if len(f.References) > 0 {
		sections = append(sections, d.theme.Subtitle.Render("  References"))
		for _, ref := range f.References {
			sections = append(sections, "  "+d.theme.AccentStyle.Render(ref))
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Left, sections...)
	d.viewport.SetContent(content)
	d.viewport.GotoTop()
}
func (d *FindingDetail) View() string {
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(d.theme.Colors.Border).
		Width(d.width).
		Height(d.height)

	title := d.theme.Subtitle.Render("  Finding Detail")
	content := lipgloss.JoinVertical(lipgloss.Left, title, "", d.viewport.View())
	return border.Render(content)
}

func wordWrap(text string, width int) string {
	if width <= 0 {
		return text
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	currentLine := "  " + words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) > width {
			lines = append(lines, currentLine)
			currentLine = "  " + word
		} else {
			currentLine += " " + word
		}
	}
	lines = append(lines, currentLine)
	return strings.Join(lines, "\n")
}
