package models

import "testing"

func TestFindingClassification_SQLInjection(t *testing.T) {
	f := Finding{
		ID:       "LAR-ENT-002",
		Title:    "SQL Injection - DB::raw() with variable interpolation",
		Severity: SeverityCritical,
		Category: "SQL Injection",
		Tags:     []string{"sqli", "owasp-a03-2021", "cwe-89", "pci-dss-6.2"},
		CWE:      "CWE-89",
		OWASP:    "A03:2021",
	}

	c := f.Classification()
	if c.VulnerabilityClass != "sql-injection" {
		t.Fatalf("class = %q, want sql-injection", c.VulnerabilityClass)
	}
	if c.AttackSurface != "database" {
		t.Fatalf("surface = %q, want database", c.AttackSurface)
	}
	if c.Impact != "data-exposure" {
		t.Fatalf("impact = %q, want data-exposure", c.Impact)
	}
	if !containsCompliance(c.Compliance, "CWE-89") || !containsCompliance(c.Compliance, "A03:2021") || !containsCompliance(c.Compliance, "PCI-DSS-6.2") {
		t.Fatalf("classification compliance missing expected values: %+v", c.Compliance)
	}
}

func TestFindingClassification_Dependency(t *testing.T) {
	f := Finding{
		ID:       "CVE-2024-12345",
		Title:    "Known vulnerable package",
		Severity: SeverityHigh,
		Category: "Dependencies",
		Scanner:  "dependency-scanner",
		Tags:     []string{"cwe-79"},
		CWE:      "CWE-79",
	}

	c := f.Classification()
	if c.VulnerabilityClass != "dependency-management" {
		t.Fatalf("class = %q, want dependency-management", c.VulnerabilityClass)
	}
	if c.AttackSurface != "supply-chain" {
		t.Fatalf("surface = %q, want supply-chain", c.AttackSurface)
	}
	if c.Impact != "supply-chain-compromise" {
		t.Fatalf("impact = %q, want supply-chain-compromise", c.Impact)
	}
}

func containsCompliance(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
