package models

import "testing"

func TestCountBySeverity(t *testing.T) {
	report := &ScanReport{
		Findings: []Finding{
			{ID: "1", Severity: SeverityCritical},
			{ID: "2", Severity: SeverityHigh},
			{ID: "3", Severity: SeverityHigh},
			{ID: "4", Severity: SeverityMedium},
			{ID: "5", Severity: SeverityInfo},
		},
	}

	counts := report.CountBySeverity()
	if counts[SeverityCritical] != 1 {
		t.Errorf("critical = %d, want 1", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 2 {
		t.Errorf("high = %d, want 2", counts[SeverityHigh])
	}
	if counts[SeverityLow] != 0 {
		t.Errorf("low = %d, want 0", counts[SeverityLow])
	}
}

func TestFindingsByCategory(t *testing.T) {
	report := &ScanReport{
		Findings: []Finding{
			{ID: "1", Category: "Injection"},
			{ID: "2", Category: "Secrets"},
			{ID: "3", Category: "Injection"},
		},
	}

	grouped := report.FindingsByCategory()
	if len(grouped["Injection"]) != 2 {
		t.Errorf("Injection count = %d, want 2", len(grouped["Injection"]))
	}
	if len(grouped["Secrets"]) != 1 {
		t.Errorf("Secrets count = %d, want 1", len(grouped["Secrets"]))
	}
}

func TestCountByClassification(t *testing.T) {
	report := &ScanReport{
		Findings: []Finding{
			{ID: "1", Category: "SQL Injection", Tags: []string{"cwe-89"}},
			{ID: "2", Category: "Dependencies", Scanner: "dependency-scanner"},
			{ID: "3", Category: "Dependencies", Scanner: "dependency-scanner"},
		},
	}

	byClass := report.CountByVulnerabilityClass()
	if byClass["sql-injection"] != 1 {
		t.Fatalf("sql-injection count = %d, want 1", byClass["sql-injection"])
	}
	if byClass["dependency-management"] != 2 {
		t.Fatalf("dependency-management count = %d, want 2", byClass["dependency-management"])
	}

	byImpact := report.CountByImpact()
	if byImpact["data-exposure"] != 1 {
		t.Fatalf("data-exposure count = %d, want 1", byImpact["data-exposure"])
	}
	if byImpact["supply-chain-compromise"] != 2 {
		t.Fatalf("supply-chain-compromise count = %d, want 2", byImpact["supply-chain-compromise"])
	}
}
