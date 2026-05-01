package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/haliminurja/vanguard/internal/models"
)

type jsonFinding struct {
	ID             string             `json:"id"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	Severity       string             `json:"severity"`
	Category       string             `json:"category"`
	Scanner        string             `json:"scanner"`
	File           string             `json:"file,omitempty"`
	Line           int                `json:"line,omitempty"`
	CodeSnippet    string             `json:"code_snippet,omitempty"`
	Remediation    string             `json:"remediation,omitempty"`
	References     []string           `json:"references,omitempty"`
	Tags           []string           `json:"tags,omitempty"`
	CWE            string             `json:"cwe,omitempty"`
	OWASP          string             `json:"owasp,omitempty"`
	Confidence     string             `json:"confidence,omitempty"`
	CVSSScore      float64            `json:"cvss_score,omitempty"`
	CVSSVector     string             `json:"cvss_vector,omitempty"`
	Classification jsonClassification `json:"classification"`
	Fingerprint    string             `json:"fingerprint,omitempty"`
}

type jsonClassification struct {
	VulnerabilityClass string   `json:"vulnerability_class"`
	AttackSurface      string   `json:"attack_surface"`
	Impact             string   `json:"impact"`
	Compliance         []string `json:"compliance,omitempty"`
}

type jsonReport struct {
	Project  jsonProject   `json:"project"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonProject struct {
	Name             string `json:"name"`
	Path             string `json:"path"`
	Framework        string `json:"framework,omitempty"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	LaravelVersion   string `json:"laravel_version,omitempty"`
	PHPVersion       string `json:"php_version,omitempty"`
}

type jsonSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByClass       map[string]int `json:"by_class,omitempty"`
	ByImpact      map[string]int `json:"by_impact,omitempty"`
	Duration      string         `json:"duration"`
	ScannersRun   []string       `json:"scanners_run"`
}
type JSONReporter struct {
	OutputDir string
}

func NewJSONReporter(outputDir string) *JSONReporter {
	if outputDir == "" {
		outputDir = "."
	}
	return &JSONReporter{OutputDir: outputDir}
}

func (r *JSONReporter) Name() string   { return "json" }
func (r *JSONReporter) Format() string { return "json" }

func (r *JSONReporter) Generate(_ context.Context, report *models.ScanReport) error {
	if err := ensureOutputDir(r.OutputDir); err != nil {
		return err
	}

	jr := jsonReport{
		Project: jsonProject{
			Name:             report.ProjectContext.ProjectName,
			Path:             report.ProjectContext.RootPath,
			Framework:        report.ProjectContext.FrameworkType,
			FrameworkVersion: report.ProjectContext.FrameworkVersion,
			LaravelVersion:   report.ProjectContext.LaravelVersion,
			PHPVersion:       report.ProjectContext.PHPVersion,
		},
		Summary: jsonSummary{
			TotalFindings: len(report.Findings),
			BySeverity:    make(map[string]int),
			ByClass:       make(map[string]int),
			ByImpact:      make(map[string]int),
			Duration:      report.Duration.String(),
			ScannersRun:   report.ScannersRun,
		},
	}

	counts := report.CountBySeverity()
	for sev, count := range counts {
		jr.Summary.BySeverity[sev.String()] = count
	}

	jr.Findings = make([]jsonFinding, 0, len(report.Findings))
	for _, f := range report.Findings {
		classification := f.Classification()
		jr.Summary.ByClass[classification.VulnerabilityClass]++
		jr.Summary.ByImpact[classification.Impact]++

		jr.Findings = append(jr.Findings, jsonFinding{
			ID:          f.ID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity.String(),
			Category:    f.Category,
			Scanner:     f.Scanner,
			File:        f.File,
			Line:        f.Line,
			CodeSnippet: f.CodeSnippet,
			Remediation: f.Remediation,
			References:  f.References,
			Tags:        f.Tags,
			CWE:         f.CWE,
			OWASP:       f.OWASP,
			Confidence:  f.Confidence,
			CVSSScore:   f.CVSSScore,
			CVSSVector:  f.CVSSVector,
			Classification: jsonClassification{
				VulnerabilityClass: classification.VulnerabilityClass,
				AttackSurface:      classification.AttackSurface,
				Impact:             classification.Impact,
				Compliance:         classification.Compliance,
			},
			Fingerprint: f.Fingerprint(),
		})
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}

	outPath := filepath.Join(r.OutputDir, "vanguard-report.json")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outPath, err)
	}

	return nil
}
