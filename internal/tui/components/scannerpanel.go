package components

import (
	"fmt"

	"vanguard/internal/models"
	"vanguard/internal/tui/theme"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ScannerPanel struct {
	scanners []models.ScannerInfo
	spinner  spinner.Model
	theme    *theme.Theme
	width    int
	height   int
}

func NewScannerPanel(t *theme.Theme) *ScannerPanel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(t.Colors.StageActive)
	return &ScannerPanel{theme: t, spinner: s}
}
func (p *ScannerPanel) SetScanners(scanners []models.ScannerInfo) {
	p.scanners = scanners
}
func (p *ScannerPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}
func (p *ScannerPanel) Tick(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	p.spinner, cmd = p.spinner.Update(msg)
	return cmd
}
func (p *ScannerPanel) View() string {
	title := p.theme.Subtitle.Render("  Scanners")
	rows := []string{title, ""}

	for _, sc := range p.scanners {
		var statusIcon string
		switch sc.Status {
		case models.ScannerPending:
			statusIcon = p.theme.PendingStage.Render("○")
		case models.ScannerRunning:
			statusIcon = p.spinner.View()
		case models.ScannerDone:
			statusIcon = p.theme.SuccessStyle.Render("✓")
		case models.ScannerError:
			statusIcon = p.theme.ErrorStyle.Render("✗")
		case models.ScannerSkipped:
			statusIcon = p.theme.Muted.Render("–")
		}

		findingBadge := ""
		if sc.FindingCount > 0 {
			findingBadge = p.theme.Muted.Render(fmt.Sprintf(" (%d)", sc.FindingCount))
		}

		name := sc.Name
		if sc.Status == models.ScannerRunning {
			name = p.theme.Bold.Render(sc.Name)
		}

		row := fmt.Sprintf("  %s %s%s", statusIcon, name, findingBadge)
		rows = append(rows, row)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	return p.theme.SidePanel.
		Width(p.width).
		Height(p.height).
		Render(content)
}
