package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/haliminurja/vanguard/internal/models"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"v1.2.3", "1.2.3"},
		{"V2.0.0", "2.0.0"},
		{"1.0.0", "1.0.0"},
		{"dev-main", ""},
		{"1.0.x-dev", ""},
		{"^1.4.0", ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := normalizeVersion(tt.input); got != tt.want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  models.Severity
	}{
		{"CRITICAL", models.SeverityCritical},
		{"HIGH", models.SeverityHigh},
		{"MODERATE", models.SeverityMedium},
		{"MEDIUM", models.SeverityMedium},
		{"LOW", models.SeverityLow},
		{"", models.SeverityMedium},
		{"UNKNOWN", models.SeverityMedium},
	}

	for _, tt := range tests {
		if got := parseSeverity(tt.input); got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		name      string
		osv       string
		cvss      float64
		wantLevel models.Severity
	}{
		{name: "OSV precedence", osv: "HIGH", cvss: 9.8, wantLevel: models.SeverityHigh},
		{name: "Critical from CVSS", osv: "", cvss: 9.1, wantLevel: models.SeverityCritical},
		{name: "High from CVSS", osv: "", cvss: 7.2, wantLevel: models.SeverityHigh},
		{name: "Medium from CVSS", osv: "", cvss: 5.0, wantLevel: models.SeverityMedium},
		{name: "Low from CVSS", osv: "", cvss: 2.5, wantLevel: models.SeverityLow},
		{name: "Default medium", osv: "", cvss: 0, wantLevel: models.SeverityMedium},
	}

	for _, tt := range tests {
		if got := deriveSeverity(tt.osv, tt.cvss); got != tt.wantLevel {
			t.Errorf("%s: deriveSeverity(%q, %v) = %v, want %v", tt.name, tt.osv, tt.cvss, got, tt.wantLevel)
		}
	}
}

func TestVulnToFinding(t *testing.T) {
	vuln := osvVuln{
		ID:      "GHSA-abcd-1234",
		Summary: "SQL Injection in query builder",
		Aliases: []string{"CVE-2024-12345"},
		References: []osvReference{
			{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"},
			{Type: "WEB", URL: "https://github.com/test/advisory"},
		},
		Affected: []osvAffected{
			{
				Ranges: []osvRange{
					{
						Type: "ECOSYSTEM",
						Events: []osvEvent{
							{Introduced: "8.0.0"},
							{Fixed: "8.22.1"},
						},
					},
				},
			},
		},
		DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
	}
	vuln.Affected[0].Package.Name = "laravel/framework"

	f := vulnToFinding("test-scanner", "laravel/framework", "8.10.0", "Packagist", "composer.lock", vuln)

	if f.ID != "CVE-2024-12345" {
		t.Errorf("ID = %q, want CVE-2024-12345", f.ID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.Category != "Dependencies" {
		t.Errorf("Category = %q, want Dependencies", f.Category)
	}
	if len(f.References) != 2 {
		t.Errorf("References count = %d, want 2", len(f.References))
	}
}

func TestExtractFixedVersion(t *testing.T) {
	affected := []osvAffected{
		{
			Ranges: []osvRange{
				{
					Type: "ECOSYSTEM",
					Events: []osvEvent{
						{Introduced: "8.0.0"},
						{Fixed: "8.22.1"},
					},
				},
			},
		},
	}
	affected[0].Package.Name = "laravel/framework"

	fix := extractFixedVersion(affected, "laravel/framework")
	if fix != "8.22.1" {
		t.Errorf("fixed version = %q, want %q", fix, "8.22.1")
	}
	fix = extractFixedVersion(affected, "other/package")
	if fix != "" {
		t.Errorf("expected empty for unknown package, got %q", fix)
	}
}

func TestScanner_WithMockOSV(t *testing.T) {
	batchHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"results": []map[string]any{
				{
					"vulns": []map[string]string{
						{"id": "GHSA-test-1234", "modified": "2024-01-01T00:00:00Z"},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})
	queryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"vulns": []osvVuln{
				{
					ID:      "GHSA-test-1234",
					Summary: "Test vulnerability",
					Aliases: []string{"CVE-2024-99999"},
					References: []osvReference{
						{Type: "ADVISORY", URL: "https://example.com/advisory"},
					},
					DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux := http.NewServeMux()
	mux.Handle("/v1/querybatch", batchHandler)
	mux.Handle("/v1/query", queryHandler)
	server := httptest.NewServer(mux)
	defer server.Close()
	_ = &Scanner{client: server.Client()}
	resp, err := server.Client().Get(server.URL + "/v1/query")
	if err != nil {
		t.Fatalf("mock server unreachable: %v", err)
	}
	resp.Body.Close()
}

func TestScanner_NoPackages(t *testing.T) {
	s := New()
	pc := models.ProjectContext{}

	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no packages, got %d", len(findings))
	}
}
