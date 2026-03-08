package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesFromFile(t *testing.T) {
	tempDir := t.TempDir()

	wrappedYaml := `
rules:
  - id: TEST-001
    title: "Wrapped format test"
    severity: high
    category: Test
    enabled: true
    condition: any
    patterns:
      - type: regex
        target: php-files
        pattern: 'foo'
`
	wrappedFilePath := filepath.Join(tempDir, "wrapped.yaml")
	if err := os.WriteFile(wrappedFilePath, []byte(wrappedYaml), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	rules, err := LoadRulesFromFile(wrappedFilePath)
	if err != nil {
		t.Fatalf("expected no error loading wrapped yaml, got: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule from wrapped yaml, got: %d", len(rules))
	}
	if rules[0].ID != "TEST-001" {
		t.Errorf("expected rule ID TEST-001, got: %s", rules[0].ID)
	}

	directYaml := `
- id: TEST-002
  title: "Direct array format test"
  severity: medium
  category: Test
  enabled: true
  condition: all
  patterns:
    - type: contains
      target: blade-files
      pattern: 'bar'
`
	directFilePath := filepath.Join(tempDir, "direct.yaml")
	if err := os.WriteFile(directFilePath, []byte(directYaml), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	rules, err = LoadRulesFromFile(directFilePath)
	if err != nil {
		t.Fatalf("expected no error loading direct yaml, got: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule from direct yaml, got: %d", len(rules))
	}
	if rules[0].ID != "TEST-002" {
		t.Errorf("expected rule ID TEST-002, got: %s", rules[0].ID)
	}
}
