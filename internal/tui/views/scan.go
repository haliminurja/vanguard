package views

import (
	"fmt"
	"strings"

	"github.com/haliminurja/vanguard/internal/eventbus"
	"github.com/haliminurja/vanguard/internal/models"
	"github.com/haliminurja/vanguard/internal/tui/components"
	"github.com/haliminurja/vanguard/internal/tui/theme"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ScanView struct {
	theme          *theme.Theme
	currentStage   models.PipelineStage
	scannerPanel   *components.ScannerPanel
	eventLog       *components.EventLog
	scanComplete   bool
	severityCounts map[models.Severity]int
	projectName    string
	laravelVersion string
	phpVersion     string
	packageCount   int
	width          int
	height         int
}

func NewScanView(t *theme.Theme) *ScanView {
	return &ScanView{
		theme:          t,
		scannerPanel:   components.NewScannerPanel(t),
		eventLog:       components.NewEventLog(t),
		severityCounts: make(map[models.Severity]int),
	}
}
func (v *ScanView) SetSize(w, h int) {
	v.width = w
	v.height = h
	overhead := 4
	if v.projectName != "" || v.laravelVersion != "" {
		overhead += 2
	}
	bodyH := h - overhead
	if bodyH < 4 {
		bodyH = 4
	}

	scannerW := int(float64(w) * 0.30)
	logW := w - scannerW - 3

	v.scannerPanel.SetSize(scannerW, bodyH)
	v.eventLog.SetSize(logW, bodyH)
}
func (v *ScanView) UpdateScanners(s []models.ScannerInfo) {
	v.scannerPanel.SetScanners(s)
}
func (v *ScanView) UpdateStage(stage models.PipelineStage) {
	v.currentStage = stage
}
func (v *ScanView) UpdateStats(counts map[models.Severity]int) {
	v.severityCounts = counts
}
func (v *ScanView) UpdateEventLog(events []eventbus.Event) {
	v.eventLog.SetEvents(events)
}
func (v *ScanView) UpdateProjectInfo(name, laravelVer, phpVer string, pkgCount int) {
	v.projectName = name
	v.laravelVersion = laravelVer
	v.phpVersion = phpVer
	v.packageCount = pkgCount
}
func (v *ScanView) SetScanComplete(complete bool) {
	v.scanComplete = complete
}
func (v *ScanView) Tick(msg tea.Msg) tea.Cmd {
	return v.scannerPanel.Tick(msg)
}
func (v *ScanView) HandleKey(msg tea.KeyMsg) {
	v.eventLog.HandleKey(msg)
}
func (v *ScanView) View(width, height int) string {
	if width == 0 || height == 0 {
		return ""
	}
	stageRow := components.RenderStageProgress(v.currentStage, v.scanComplete, v.theme, width)
	sep := components.RenderSeparator(v.theme, width)
	infoRow := v.renderProjectInfo(width)
	statsRow := components.RenderLiveStats(v.severityCounts, v.theme, width)
	scannerView := v.scannerPanel.View()
	logView := v.eventLog.View()
	body := lipgloss.JoinHorizontal(lipgloss.Top, scannerView, " ", logView)

	rows := []string{stageRow, sep}
	if infoRow != "" {
		rows = append(rows, infoRow, sep)
	}
	rows = append(rows, statsRow, sep, body)

	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (v *ScanView) renderProjectInfo(width int) string {
	if v.projectName == "" && v.laravelVersion == "" {
		return ""
	}

	var parts []string
	if v.projectName != "" {
		parts = append(parts, v.theme.Bold.Render(v.projectName))
	}
	if v.laravelVersion != "" {
		parts = append(parts, v.theme.AccentStyle.Render(fmt.Sprintf("Laravel %s", v.laravelVersion)))
	}
	if v.phpVersion != "" {
		parts = append(parts, v.theme.AccentStyle.Render(fmt.Sprintf("PHP %s", v.phpVersion)))
	}
	if v.packageCount > 0 {
		parts = append(parts, v.theme.Muted.Render(fmt.Sprintf("%d packages", v.packageCount)))
	}

	row := strings.Join(parts, v.theme.Muted.Render("  ·  "))
	return lipgloss.PlaceHorizontal(width, lipgloss.Center, row)
}
