package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"vanguard/internal/config"
	"vanguard/internal/eventbus"
	"vanguard/internal/models"
	"vanguard/internal/orchestrator"
	"vanguard/internal/tui"
	"vanguard/internal/tui/banner"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	failOn string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Initiate an elite security patrol (scan) on your project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]
		if failOn != "" {
			validSeverities := map[string]bool{
				"info": true, "low": true, "medium": true, "high": true, "critical": true,
			}
			if !validSeverities[strings.ToLower(failOn)] {
				return fmt.Errorf("invalid --fail-on value %q: must be one of info, low, medium, high, critical", failOn)
			}
		}

		cfg, err := config.Load(targetPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		if outputFmt != "tui" {
			cfg.Output.Formats = parseOutputFormats(outputFmt)
			return runHeadless(cfg, targetPath)
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return runHeadless(cfg, targetPath)
		}

		return runWithTUI(cfg, targetPath)
	},
}

func configureOrch(orch *orchestrator.Orchestrator) {
}

func runWithTUI(cfg *config.Config, targetPath string) error {
	bus := eventbus.New()
	model := tui.NewApp(bus, targetPath, Version)

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	bridge := eventbus.NewBridge(bus, p)
	bridge.Start()
	defer bridge.Stop()
	var finalReport *models.ScanReport
	bus.Subscribe(eventbus.EventScanCompleted, func(e eventbus.Event) {
		data := e.Data.(eventbus.ScanCompletedData)
		finalReport = data.Report
	})

	go func() {
		orch := orchestrator.New(bus, cfg, targetPath, Version)
		configureOrch(orch)
		if err := orch.Run(context.Background()); err != nil {
			bus.Publish(eventbus.NewEvent(eventbus.EventScanFailed, eventbus.ScanFailedData{
				Error: err,
			}))
		}
	}()

	_, err := p.Run()
	if err != nil {
		return err
	}
	return checkFailOn(finalReport)
}

func runHeadless(cfg *config.Config, targetPath string) error {
	fmt.Println(banner.Render(Version))

	bus := eventbus.New()

	dim := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#9E9E9E"})
	accent := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#5E35B1", Dark: "#B388FF"}).Bold(true)
	sevStyles := map[models.Severity]*lipgloss.Style{
		models.SeverityCritical: ptr(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5252")).Bold(true)),
		models.SeverityHigh:     ptr(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB74D")).Bold(true)),
		models.SeverityMedium:   ptr(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD54F"))),
		models.SeverityLow:      ptr(lipgloss.NewStyle().Foreground(lipgloss.Color("#81C784"))),
		models.SeverityInfo:     ptr(lipgloss.NewStyle().Foreground(lipgloss.Color("#64B5F6"))),
	}
	var finalReport *models.ScanReport
	bus.Subscribe(eventbus.EventStageStarted, func(e eventbus.Event) {
		data, ok := e.Data.(eventbus.StageStartedData)
		if !ok {
			return
		}
		fmt.Printf("  %s %s\n", accent.Render("●"), data.Stage)
	})

	bus.Subscribe(eventbus.EventFindingDiscovered, func(e eventbus.Event) {
		data, ok := e.Data.(eventbus.FindingDiscoveredData)
		if !ok {
			return
		}
		f := data.Finding
		style := sevStyles[f.Severity]
		fmt.Printf("    %s %s\n", style.Render(fmt.Sprintf("[%s]", f.Severity)), f.Title)
		if f.File != "" {
			if f.Line > 0 {
				fmt.Printf("      %s\n", dim.Render(fmt.Sprintf("%s:%d", f.File, f.Line)))
			} else {
				fmt.Printf("      %s\n", dim.Render(f.File))
			}
		}
	})

	bus.Subscribe(eventbus.EventScannerCompleted, func(e eventbus.Event) {
		data, ok := e.Data.(eventbus.ScannerCompletedData)
		if !ok {
			return
		}
		fmt.Printf("  %s %s — %d findings\n", dim.Render("✓"), data.Name, data.FindingCount)
	})

	bus.Subscribe(eventbus.EventLogMessage, func(e eventbus.Event) {
		data, ok := e.Data.(eventbus.LogMessageData)
		if !ok {
			return
		}
		fmt.Printf("  %s %s\n", dim.Render("["+data.Level+"]"), data.Message)
	})

	bus.Subscribe(eventbus.EventScanCompleted, func(e eventbus.Event) {
		data, ok := e.Data.(eventbus.ScanCompletedData)
		if !ok {
			return
		}
		r := data.Report
		finalReport = r
		counts := r.CountBySeverity()
		fmt.Println()
		fmt.Printf("  %s %d findings in %s\n", accent.Render("Done."), len(r.Findings), r.Duration.Round(1e6))
		for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
			if c := counts[sev]; c > 0 {
				style := sevStyles[sev]
				fmt.Printf("    %s %d\n", style.Render(fmt.Sprintf("%-10s", sev)), c)
			}
		}
		fmt.Println()

	})

	orch := orchestrator.New(bus, cfg, targetPath, Version)
	configureOrch(orch)
	if err := orch.Run(context.Background()); err != nil {
		return err
	}

	return checkFailOn(finalReport)
}
func checkFailOn(report *models.ScanReport) error {
	if failOn == "" || report == nil {
		return nil
	}

	threshold := models.ParseSeverity(failOn)

	for _, f := range report.Findings {
		if f.Severity >= threshold {
			counts := report.CountBySeverity()
			var parts []string
			for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
				if sev >= threshold {
					if c := counts[sev]; c > 0 {
						parts = append(parts, fmt.Sprintf("%d %s", c, sev))
					}
				}
			}
			return fmt.Errorf("findings exceed --fail-on %s threshold: %s", failOn, strings.Join(parts, ", "))
		}
	}

	return nil
}

func ptr(s lipgloss.Style) *lipgloss.Style { return &s }
func parseOutputFormats(s string) []string {
	var formats []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			formats = append(formats, f)
		}
	}
	return formats
}

func init() {
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "exit code 1 if findings at or above this severity (info, low, medium, high, critical)")
	rootCmd.AddCommand(scanCmd)
}
