package reporter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/haliminurja/vanguard/internal/models"
)

func testReport() *models.ScanReport {
	return &models.ScanReport{
		ProjectContext: models.ProjectContext{
			ProjectName:      "test/app",
			RootPath:         "/tmp/test",
			LaravelVersion:   "^11.0",
			FrameworkType:    "laravel",
			FrameworkVersion: "^11.0",
			PHPVersion:       "^8.2",
		},
		Findings: []models.Finding{
			{
				ID:          "TEST-001",
				Title:       "Test Critical Finding",
				Description: "A critical test finding.",
				Severity:    models.SeverityCritical,
				Category:    "Test",
				Scanner:     "test-scanner",
				File:        "app/Test.php",
				Line:        42,
				CodeSnippet: "$password = 'hardcoded';",
				Remediation: "Fix it.",
				References:  []string{"https://example.com"},
				CVSSScore:   9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			{
				ID:       "TEST-002",
				Title:    "Test Low Finding",
				Severity: models.SeverityLow,
				Category: "Test",
				Scanner:  "test-scanner",
				File:     "config/app.php",
				Line:     10,
			},
		},
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Duration:    500 * time.Millisecond,
		ScannersRun: []string{"test-scanner"},
	}
}

func TestJSONReporter(t *testing.T) {
	dir := t.TempDir()
	r := NewJSONReporter(dir)

	if r.Name() != "json" {
		t.Errorf("Name() = %q, want %q", r.Name(), "json")
	}

	err := r.Generate(context.Background(), testReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "vanguard-report.json"))
	if err != nil {
		t.Fatalf("report file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "TEST-001") {
		t.Error("JSON report should contain finding ID")
	}
	if !strings.Contains(content, "test/app") {
		t.Error("JSON report should contain project name")
	}
	if !strings.Contains(content, "framework") || !strings.Contains(content, "cvss_score") {
		t.Error("JSON report should contain project and finding classification metadata")
	}
	if !strings.Contains(content, "classification") || !strings.Contains(content, "vulnerability_class") {
		t.Error("JSON report should contain deep finding classification")
	}
}

func TestSARIFReporter(t *testing.T) {
	dir := t.TempDir()
	r := NewSARIFReporter(dir, "test")

	if r.Name() != "sarif" {
		t.Errorf("Name() = %q, want %q", r.Name(), "sarif")
	}

	err := r.Generate(context.Background(), testReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "vanguard-report.sarif"))
	if err != nil {
		t.Fatalf("SARIF file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "sarif-schema-2.1.0") {
		t.Error("SARIF report should contain schema reference")
	}
	if !strings.Contains(content, "TEST-001") {
		t.Error("SARIF report should contain rule ID")
	}
	if !strings.Contains(content, "vanguard") {
		t.Error("SARIF report should contain tool name")
	}
	if !strings.Contains(content, "vulnerability-class") {
		t.Error("SARIF report should contain vulnerability classification")
	}
}

func TestHTMLReporter(t *testing.T) {
	dir := t.TempDir()
	r := NewHTMLReporter(dir, "test")

	err := r.Generate(context.Background(), testReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "vanguard-report.html"))
	if err != nil {
		t.Fatalf("HTML file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "<!DOCTYPE html>") {
		t.Error("HTML report should contain doctype")
	}
	if !strings.Contains(content, "Test Critical Finding") {
		t.Error("HTML report should contain finding title")
	}
	if !strings.Contains(content, "Critical") {
		t.Error("HTML report should contain severity badge")
	}
	if !strings.Contains(content, "Laravel ^11.0") {
		t.Error("HTML report should contain framework classification")
	}
}

func TestMarkdownReporter(t *testing.T) {
	dir := t.TempDir()
	r := NewMarkdownReporter(dir, "test")

	err := r.Generate(context.Background(), testReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "vanguard-report.md"))
	if err != nil {
		t.Fatalf("Markdown file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# Vanguard Security Report") {
		t.Error("Markdown report should contain title")
	}
	if !strings.Contains(content, "TEST-001") {
		t.Error("Markdown report should contain finding ID")
	}
	if !strings.Contains(content, "Critical") {
		t.Error("Markdown report should contain severity section")
	}
	if !strings.Contains(content, "**Framework:** Laravel ^11.0") {
		t.Error("Markdown report should contain framework classification")
	}
	if !strings.Contains(content, "**Class:**") || !strings.Contains(content, "**Impact:**") {
		t.Error("Markdown report should contain deep finding classification")
	}
}

func TestReportersCreateOutputDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "reports")
	r := NewJSONReporter(dir)

	if err := r.Generate(context.Background(), testReport()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vanguard-report.json")); err != nil {
		t.Fatalf("expected report in nested output dir: %v", err)
	}
}
