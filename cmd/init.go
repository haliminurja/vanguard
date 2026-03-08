package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"vanguard/internal/tui/banner"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize VANGUARD in the current project",
	Long:  "Creates a default vanguard.yaml configuration file in the project root.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(banner.Render(Version))
		fmt.Println()

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		configPath := filepath.Join(cwd, "vanguard.yaml")
		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("    %s VANGUARD is already initialized (vanguard.yaml exists).\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD54F")).Render("!"))
			return nil
		}

		template := `# VANGUARD Security Configuration
# For more info, visit: https://github.com/haliminurja/vanguard

# Minimum severity to report (info, low, medium, high, critical)
severity: info

# Scanners configuration
scanners:
  # List of scanner names to enable or disable
  # enable: ["rules-scanner", "dependency-scanner"]
  # disable: []
  
  # Ignore specific directories for all scanners
  ignore_dirs: ["vendor", "node_modules", "storage", "public", "tests"]

# Ignore rules or paths
ignore:
  # Files to skip (glob patterns)
  paths:
    - "tests/*"
    - "database/factories/*"
  # Rule IDs to ignore globally
  rules: []

# Output settings
output:
  formats: ["tui", "html", "markdown"]
  # dir: "./reports"
`

		if err := os.WriteFile(configPath, []byte(template), 0644); err != nil {
			return fmt.Errorf("failed to write vanguard.yaml: %w", err)
		}

		accent := lipgloss.NewStyle().Foreground(lipgloss.Color("#B388FF")).Bold(true)
		fmt.Printf("    %s Created %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#81C784")).Render("✓"),
			accent.Render("vanguard.yaml"))

		if _, err := os.Stat(".git"); err == nil {
			hookPath := filepath.Join(".git", "hooks", "pre-commit")
			hookContent := `#!/bin/sh
# VANGUARD Pre-commit Hook
# Prevents committing security vulnerabilities

vanguard scan . --severity high --output-format tui
if [ $? -ne 0 ]; then
  echo "\033[31m❌ VANGUARD found high-severity vulnerabilities. Commit aborted.\033[0m"
  exit 1
fi
`
			if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err == nil {
				fmt.Printf("    %s Installed Git %s\n",
					lipgloss.NewStyle().Foreground(lipgloss.Color("#81C784")).Render("✓"),
					accent.Render("pre-commit hook"))
			}
		}

		fmt.Println("\n    You can now run 'vanguard scan .' to check your project.")
		fmt.Println("    Edit vanguard.yaml to customize ignore lists or severity thresholds.")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
