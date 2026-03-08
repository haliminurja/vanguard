package theme

import (
	"vanguard/internal/models"

	"github.com/charmbracelet/lipgloss"
)

type Colors struct {
	Critical lipgloss.AdaptiveColor
	High     lipgloss.AdaptiveColor
	Medium   lipgloss.AdaptiveColor
	Low      lipgloss.AdaptiveColor
	Info     lipgloss.AdaptiveColor

	Primary    lipgloss.AdaptiveColor
	Secondary  lipgloss.AdaptiveColor
	Accent     lipgloss.AdaptiveColor
	Subtle     lipgloss.AdaptiveColor
	Text       lipgloss.AdaptiveColor
	TextDim    lipgloss.AdaptiveColor
	Border     lipgloss.AdaptiveColor
	Success    lipgloss.AdaptiveColor
	Warning    lipgloss.AdaptiveColor
	Error      lipgloss.AdaptiveColor
	Background lipgloss.AdaptiveColor

	StageActive   lipgloss.AdaptiveColor
	StageComplete lipgloss.AdaptiveColor
	StagePending  lipgloss.AdaptiveColor
}

func DefaultColors() Colors {
	return Colors{
		Critical:   lipgloss.AdaptiveColor{Light: "#E11D48", Dark: "#FB7185"}, // Rose
		High:       lipgloss.AdaptiveColor{Light: "#EA580C", Dark: "#FB923C"}, // Orange
		Medium:     lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}, // Amber
		Low:        lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34D399"}, // Emerald
		Info:       lipgloss.AdaptiveColor{Light: "#0284C7", Dark: "#38BDF8"}, // Sky
		Primary:    lipgloss.AdaptiveColor{Light: "#4338CA", Dark: "#6366F1"}, // Indigo
		Secondary:  lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"}, // Slate
		Accent:     lipgloss.AdaptiveColor{Light: "#7E22CE", Dark: "#A855F7"}, // Purple
		Subtle:     lipgloss.AdaptiveColor{Light: "#F1F5F9", Dark: "#1E293B"}, // Slate Subtle
		Text:       lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#F8FAFC"},
		TextDim:    lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#64748B"},
		Border:     lipgloss.AdaptiveColor{Light: "#4F46E5", Dark: "#818CF8"},
		Success:    lipgloss.AdaptiveColor{Light: "#10B981", Dark: "#34D399"},
		Warning:    lipgloss.AdaptiveColor{Light: "#F59E0B", Dark: "#FBBF24"},
		Error:      lipgloss.AdaptiveColor{Light: "#EF4444", Dark: "#F87171"},
		Background: lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0F172A"},

		StageActive:   lipgloss.AdaptiveColor{Light: "#4F46E5", Dark: "#818CF8"},
		StageComplete: lipgloss.AdaptiveColor{Light: "#10B981", Dark: "#34D399"},
		StagePending:  lipgloss.AdaptiveColor{Light: "#94A3B8", Dark: "#475569"},
	}
}

type Theme struct {
	Colors         Colors
	HeaderBar      lipgloss.Style
	FooterBar      lipgloss.Style
	ContentPanel   lipgloss.Style
	SidePanel      lipgloss.Style
	ActiveStage    lipgloss.Style
	CompletedStage lipgloss.Style
	PendingStage   lipgloss.Style
	SeverityStyles map[models.Severity]lipgloss.Style
	TableHeader    lipgloss.Style
	TableRow       lipgloss.Style
	TableRowAlt    lipgloss.Style
	TableSelected  lipgloss.Style
	Title          lipgloss.Style
	Subtitle       lipgloss.Style
	Muted          lipgloss.Style
	Bold           lipgloss.Style
	Code           lipgloss.Style
	AccentStyle    lipgloss.Style
	SuccessStyle   lipgloss.Style
	ErrorStyle     lipgloss.Style
	WarningStyle   lipgloss.Style
}

func DefaultTheme() *Theme {
	c := DefaultColors()

	t := &Theme{
		Colors: c,

		HeaderBar: lipgloss.NewStyle().
			Background(c.Primary).
			Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"}).
			Padding(0, 1).
			Bold(true),

		FooterBar: lipgloss.NewStyle().
			Foreground(c.TextDim).
			Padding(0, 1),

		ContentPanel: lipgloss.NewStyle().
			Padding(0, 1),

		SidePanel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(c.Border).
			Padding(0, 1),

		ActiveStage: lipgloss.NewStyle().
			Foreground(c.StageActive).
			Bold(true),

		CompletedStage: lipgloss.NewStyle().
			Foreground(c.StageComplete),

		PendingStage: lipgloss.NewStyle().
			Foreground(c.StagePending),

		SeverityStyles: map[models.Severity]lipgloss.Style{
			models.SeverityCritical: lipgloss.NewStyle().
				Background(c.Critical).
				Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"}).
				Bold(true).
				Padding(0, 1),
			models.SeverityHigh: lipgloss.NewStyle().
				Background(c.High).
				Foreground(lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#1A1A1A"}).
				Bold(true).
				Padding(0, 1),
			models.SeverityMedium: lipgloss.NewStyle().
				Background(c.Medium).
				Foreground(lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#1A1A1A"}).
				Padding(0, 1),
			models.SeverityLow: lipgloss.NewStyle().
				Background(c.Low).
				Foreground(lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#1A1A1A"}).
				Padding(0, 1),
			models.SeverityInfo: lipgloss.NewStyle().
				Background(c.Info).
				Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"}).
				Padding(0, 1),
		},

		TableHeader: lipgloss.NewStyle().
			Bold(true).
			Foreground(c.Accent).
			BorderBottom(true).
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(c.Border),

		TableRow: lipgloss.NewStyle().
			Foreground(c.Text),

		TableRowAlt: lipgloss.NewStyle().
			Foreground(c.Text),

		TableSelected: lipgloss.NewStyle().
			Foreground(c.Primary).
			Bold(true).
			Background(lipgloss.AdaptiveColor{Light: "#EDE7F6", Dark: "#2A2040"}),

		Title: lipgloss.NewStyle().
			Foreground(c.Text).
			Bold(true),

		Subtitle: lipgloss.NewStyle().
			Foreground(c.Secondary).
			Bold(true),

		Muted: lipgloss.NewStyle().
			Foreground(c.TextDim),

		Bold: lipgloss.NewStyle().
			Bold(true),

		Code: lipgloss.NewStyle().
			Background(lipgloss.AdaptiveColor{Light: "#F5F5F5", Dark: "#2D2D2D"}).
			Foreground(lipgloss.AdaptiveColor{Light: "#D32F2F", Dark: "#FF8A80"}).
			Padding(0, 1),

		AccentStyle: lipgloss.NewStyle().
			Foreground(c.Accent),

		SuccessStyle: lipgloss.NewStyle().
			Foreground(c.Success),

		ErrorStyle: lipgloss.NewStyle().
			Foreground(c.Error),

		WarningStyle: lipgloss.NewStyle().
			Foreground(c.Warning),
	}

	return t
}
func (t *Theme) SeverityColor(s models.Severity) lipgloss.AdaptiveColor {
	switch s {
	case models.SeverityCritical:
		return t.Colors.Critical
	case models.SeverityHigh:
		return t.Colors.High
	case models.SeverityMedium:
		return t.Colors.Medium
	case models.SeverityLow:
		return t.Colors.Low
	case models.SeverityInfo:
		return t.Colors.Info
	default:
		return t.Colors.TextDim
	}
}
