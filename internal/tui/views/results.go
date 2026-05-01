package views

import (
	"fmt"
	"sort"
	"time"

	"github.com/haliminurja/vanguard/internal/models"
	"github.com/haliminurja/vanguard/internal/store"
	"github.com/haliminurja/vanguard/internal/tui/components"
	"github.com/haliminurja/vanguard/internal/tui/theme"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SortColumn int

const (
	SortBySeverity SortColumn = iota
	SortByCategory
	SortByFile
)

func (s SortColumn) String() string {
	switch s {
	case SortBySeverity:
		return "Severity"
	case SortByCategory:
		return "Category"
	case SortByFile:
		return "File"
	default:
		return "Unknown"
	}
}

type ResultsView struct {
	theme         *theme.Theme
	report        *models.ScanReport
	table         table.Model
	findings      []models.Finding
	sortColumn    SortColumn
	sortAscending bool
	detail        *components.FindingDetail
	width         int
	height        int
	focusPanel    int
	tabKey        key.Binding
	sortKey       key.Binding
	filterKey     key.Binding
	currentFilter string
	categories    []string
	categoryIdx   int
}

func NewResultsView(t *theme.Theme, report *models.ScanReport) *ResultsView {
	v := &ResultsView{
		theme:    t,
		report:   report,
		findings: make([]models.Finding, len(report.Findings)),
		detail:   components.NewFindingDetail(t),
		tabKey: key.NewBinding(
			key.WithKeys("tab"),
		),
		sortKey: key.NewBinding(
			key.WithKeys("s"),
		),
		filterKey: key.NewBinding(
			key.WithKeys("f"),
		),
		currentFilter: "All",
	}
	v.extractCategories()
	copy(v.findings, report.Findings)
	v.sortFindings()
	v.buildTable()
	if len(v.findings) > 0 {
		v.detail.SetFinding(&v.findings[0])
	}

	return v
}
func (v *ResultsView) SetSize(w, h int) {
	v.width = w
	v.height = h
	overheadH := 6
	bodyH := h - overheadH
	if bodyH < 6 {
		bodyH = 6
	}

	tableW := int(float64(w) * 0.50)
	detailW := w - tableW - 3

	v.table.SetWidth(tableW)
	v.table.SetHeight(bodyH - 2)
	v.detail.SetSize(detailW, bodyH)
}

func (v *ResultsView) buildTable() {
	columns := []table.Column{
		{Title: "Sev", Width: 10},
		{Title: "Category", Width: 14},
		{Title: "Title", Width: 28},
		{Title: "File", Width: 22},
		{Title: "Line", Width: 6},
	}

	var rows []table.Row
	for _, f := range v.findings {
		rows = append(rows, table.Row{
			f.Severity.String(),
			truncate(f.Category, 12),
			truncate(f.Title, 26),
			truncate(f.File, 20),
			fmt.Sprintf("%d", f.Line),
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(20),
	)

	s := table.DefaultStyles()
	s.Header = v.theme.TableHeader
	s.Selected = v.theme.TableSelected
	t.SetStyles(s)

	v.table = t
}

func (v *ResultsView) sortFindings() {
	sort.SliceStable(v.findings, func(i, j int) bool {
		switch v.sortColumn {
		case SortBySeverity:
			return v.findings[i].Severity > v.findings[j].Severity
		case SortByCategory:
			return v.findings[i].Category < v.findings[j].Category
		case SortByFile:
			return v.findings[i].File < v.findings[j].File
		}
		return false
	})
}

func (v *ResultsView) extractCategories() {
	cats := make(map[string]bool)
	for _, f := range v.report.Findings {
		cats[f.Category] = true
	}
	v.categories = []string{"All"}
	var sortedCats []string
	for c := range cats {
		sortedCats = append(sortedCats, c)
	}
	sort.Strings(sortedCats)
	v.categories = append(v.categories, sortedCats...)
}
func (v *ResultsView) HandleKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, v.tabKey):
		v.focusPanel = (v.focusPanel + 1) % 2
		v.table.Focus()
		if v.focusPanel == 1 {
			v.table.Blur()
		}
		return nil
	case key.Matches(msg, v.sortKey):
		v.sortColumn = (v.sortColumn + 1) % 3
		v.sortFindings()
		v.buildTable()
		return nil
	case key.Matches(msg, v.filterKey):
		v.categoryIdx = (v.categoryIdx + 1) % len(v.categories)
		v.currentFilter = v.categories[v.categoryIdx]
		v.applyFilterAndSort()
		return nil
	}

	if v.focusPanel == 0 {
		var cmd tea.Cmd
		v.table, cmd = v.table.Update(msg)
		idx := v.table.Cursor()
		if idx >= 0 && idx < len(v.findings) {
			v.detail.SetFinding(&v.findings[idx])
		}
		return cmd
	}
	v.detail.HandleKey(msg)
	return nil
}

func (v *ResultsView) applyFilterAndSort() {
	var filtered []models.Finding
	for _, f := range v.report.Findings {
		if v.currentFilter == "All" || f.Category == v.currentFilter {
			filtered = append(filtered, f)
		}
	}
	v.findings = filtered
	v.sortFindings()
	v.buildTable()
	if len(v.findings) > 0 {
		v.detail.SetFinding(&v.findings[0])
		v.table.SetCursor(0)
	}
}
func (v *ResultsView) View(width, height int) string {
	if width == 0 || height == 0 {
		return ""
	}
	summary := v.renderSummary(width)
	sep := components.RenderSeparator(v.theme, width)
	sortInfo := v.theme.Muted.Render(fmt.Sprintf("  Sorted by: %s  |  Filter: %s  |  Panel: %s",
		v.sortColumn.String(), v.currentFilter, panelName(v.focusPanel)))
	tableView := v.renderTable()
	detailView := v.detail.View()
	body := lipgloss.JoinHorizontal(lipgloss.Top, tableView, " ", detailView)

	return lipgloss.JoinVertical(lipgloss.Left,
		summary,
		sep,
		sortInfo,
		body,
	)
}

func (v *ResultsView) renderSummary(width int) string {
	counts := v.report.CountBySeverity()
	total := len(v.report.Findings)
	pc := v.report.ProjectContext

	duration := v.report.Duration.Round(time.Millisecond)
	durationStr := duration.String()

	if prev, _ := store.LastRecord(v.report.ProjectContext.RootPath); prev != nil {
		if d, err := time.ParseDuration(prev.Duration); err == nil && d > 0 {
			delta := v.report.Duration - d
			pct := float64(delta) / float64(d) * 100
			if delta > 0 {
				durationStr += fmt.Sprintf(" (%s slower)", lipgloss.NewStyle().Foreground(v.theme.Colors.Critical).Render(fmt.Sprintf("+%.1f%%", pct)))
			} else if delta < 0 {
				durationStr += fmt.Sprintf(" (%s faster)", lipgloss.NewStyle().Foreground(v.theme.Colors.Low).Render(fmt.Sprintf("%.1f%%", pct)))
			}
		}
	}

	header := v.theme.Title.Render(fmt.Sprintf("  Scan Complete  —  %d findings in %s",
		total, durationStr))
	var infoParts []string
	if pc.ProjectName != "" {
		infoParts = append(infoParts, pc.ProjectName)
	}
	if pc.LaravelVersion != "" {
		infoParts = append(infoParts, fmt.Sprintf("Laravel %s", pc.LaravelVersion))
	}
	if pc.PHPVersion != "" {
		infoParts = append(infoParts, fmt.Sprintf("PHP %s", pc.PHPVersion))
	}
	if len(pc.InstalledPackages) > 0 {
		infoParts = append(infoParts, fmt.Sprintf("%d packages", len(pc.InstalledPackages)))
	}
	infoParts = append(infoParts, fmt.Sprintf("%d scanners", len(v.report.ScannersRun)))

	sep := v.theme.Muted.Render(" · ")
	var styledParts []string
	for _, p := range infoParts {
		styledParts = append(styledParts, v.theme.AccentStyle.Render(p))
	}
	infoLine := lipgloss.JoinHorizontal(lipgloss.Center, interleave(styledParts, sep)...)

	stats := components.RenderLiveStats(counts, v.theme, width)

	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.PlaceHorizontal(width, lipgloss.Center, header),
		lipgloss.PlaceHorizontal(width, lipgloss.Center, infoLine),
		"",
		stats,
	)
}
func interleave(items []string, sep string) []string {
	if len(items) == 0 {
		return nil
	}
	result := make([]string, 0, len(items)*2-1)
	for i, item := range items {
		if i > 0 {
			result = append(result, sep)
		}
		result = append(result, item)
	}
	return result
}

func (v *ResultsView) renderTable() string {
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(v.theme.Colors.Border)

	if v.focusPanel == 0 {
		border = border.BorderForeground(v.theme.Colors.Primary).
			BorderStyle(lipgloss.ThickBorder())
	}

	return border.Render(v.table.View())
}

func panelName(idx int) string {
	if idx == 0 {
		return "Table"
	}
	return "Detail"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-2] + ".."
}
