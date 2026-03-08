package cmd

import (
	"fmt"
	"runtime/debug"
	"sync"

	"vanguard/internal/config"
	"vanguard/internal/tui/banner"
	"vanguard/internal/updater"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	verbose   bool
	noColor   bool
	outputFmt string
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var (
	updateNotice string
	updateOnce   sync.Once
	updateDone   = make(chan struct{})
)

func init() {
	info, ok := debug.ReadBuildInfo()

	if Version == "dev" {
		if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
	if Commit == "none" {
		if ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					Commit = s.Value[:7]
					break
				}
			}
		}
	}
}

var rootCmd = &cobra.Command{
	Use:   "vanguard",
	Short: "VANGUARD: Your Elite Security Sentinel",
	Long:  banner.Render(Version),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		go func() {
			defer close(updateDone)
			vanguardDir, err := config.Dir()
			if err != nil {
				return
			}
			updateNotice = updater.CheckForUpdate(Version, vanguardDir)
		}()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		<-updateDone
		if updateNotice != "" {
			updateStyle := lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#E65100", Dark: "#FFB74D"}).
				Bold(true)
			borderStyle := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.AdaptiveColor{Light: "#E65100", Dark: "#FFB74D"}).
				Padding(0, 1)
			fmt.Println()
			fmt.Println(borderStyle.Render(updateStyle.Render("⬆ Update Available") + "\n" + updateNotice))
			fmt.Println()
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(banner.RenderWithBox(Version))
		fmt.Println()

		dim := lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#9E9E9E"})
		accent := lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#5E35B1", Dark: "#B388FF"}).
			Bold(true)

		fmt.Println(accent.Render("    vanguard scan <path>") + dim.Render("    Initiate a security patrol over your project"))
		fmt.Println(accent.Render("    vanguard --help") + dim.Render("         Show all commands"))
		fmt.Println()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable color output")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "tui", "output mode: tui (interactive), or comma-separated formats (json,sarif,html,markdown)")
}
