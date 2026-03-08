package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Generate CI/CD configuration files",
	Long:  "Commands to generate production-ready CI/CD workflows for GitHub Actions or GitLab CI.",
}

var ciGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Generate GitHub Actions workflow",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		workflowDir := filepath.Join(cwd, ".github", "workflows")
		if err := os.MkdirAll(workflowDir, 0755); err != nil {
			return fmt.Errorf("failed to create .github/workflows directory: %w", err)
		}

		workflowPath := filepath.Join(workflowDir, "vanguard.yml")
		template := `name: VANGUARD Security Scan

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]
  schedule:
    - cron: '0 0 * * *'

jobs:
  scan:
    name: VANGUARD Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'
          cache: true

      - name: Install VANGUARD
        run: go install github.com/haliminurja/vanguard@latest

      - name: Set up VANGUARD
        run: vanguard init

      - name: Run VANGUARD Scan
        run: vanguard scan . --output-format sarif --output-dir .
        continue-on-error: true

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vanguard-report.sarif
          category: vanguard-security
`
		if err := os.WriteFile(workflowPath, []byte(template), 0644); err != nil {
			return fmt.Errorf("failed to write workflow file: %w", err)
		}

		successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#81C784")).Render("✓")
		pathStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#B388FF")).Bold(true).Render(".github/workflows/vanguard.yml")
		fmt.Printf("    %s Generated %s\n", successStyle, pathStyle)
		fmt.Println("    VANGUARD is now configured to run on every push and PR.")
		return nil
	},
}

var ciGitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Generate GitLab CI configuration snippet",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("    Add the following to your .gitlab-ci.yml:")
		fmt.Print(`
vanguard_scan:
  stage: test
  image: golang:1.24
  script:
    - go install github.com/haliminurja/vanguard@latest
    - vanguard scan . --output-format json
  artifacts:
    when: always
    paths:
      - vanguard-report.json
`)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ciCmd)
	ciCmd.AddCommand(ciGitHubCmd)
	ciCmd.AddCommand(ciGitLabCmd)
}
