package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"vanguard/internal/config"
	"vanguard/internal/models"
)

func boolPtr(b bool) *bool { return &b }

func TestRulesScanner_RegexMatch(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Service.php"), []byte(`<?php
$password = "hardcoded123";
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-001",
			Title:    "Hardcoded password",
			Severity: "high",
			Category: "Secrets",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `\$password\s*=\s*"[a-zA-Z0-9]+"`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "TEST-001" {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, "TEST-001")
	}
	if findings[0].Line != 2 {
		t.Errorf("finding line = %d, want 2", findings[0].Line)
	}
}

func TestRulesScanner_ContainsMatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET_KEY=abc123\n"), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-002",
			Title:    "Secret in env",
			Severity: "medium",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "env-files", Pattern: "SECRET_KEY"},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestRulesScanner_NegativePattern(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Model.php"), []byte(`<?php
class User extends Model {
}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-003",
			Title:    "Missing fillable",
			Severity: "medium",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "php-files", Pattern: "$fillable", Negative: true},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})

	if len(findings) != 1 {
		t.Errorf("expected 1 finding for negative pattern, got %d", len(findings))
	}
}

func TestRulesScanner_DisabledRule(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=abc\n"), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-004",
			Enabled: boolPtr(false),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "env-files", Pattern: "SECRET"},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})

	if len(findings) != 0 {
		t.Errorf("disabled rule should produce no findings, got %d", len(findings))
	}
}

func TestRulesScanner_FileExists(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env.production"), []byte(""), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-005",
			Title:    "Production env file exists",
			Severity: "low",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "file-exists", Pattern: ".env.production"},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})

	if len(findings) != 1 {
		t.Errorf("expected 1 finding for file-exists, got %d", len(findings))
	}
}

func TestRulesScanner_Multiline(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "resources", "views"), 0755)
	os.WriteFile(filepath.Join(dir, "resources", "views", "form.blade.php"), []byte(`<form action="/submit" method="POST">
    <input type="text" name="name" />
</form>
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-006",
			Title:    "Missing CSRF in form",
			Severity: "high",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex-multiline", Target: "blade-files", Pattern: `(?s)<form[^>]*>[^@]*?</form>`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for multiline regex, got %d", len(findings))
	}
}

func TestRulesScanner_UnescapedBlade(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "resources", "views"), 0755)
	os.WriteFile(filepath.Join(dir, "resources", "views", "show.blade.php"), []byte(`Hello {!! $name !!}`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-007",
			Title:   "Unescaped Blade output",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "blade-files", Pattern: `\{!![^}]+!!\}`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unescaped output, got %d", len(findings))
	}
}

func TestRulesScanner_RawSQL(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Repo.php"), []byte(`<?php
$users = DB::select("select * from users where id=".$request->id);
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-008",
			Title:   "Raw SQL with request",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `(DB::raw|DB::select|whereRaw)\s*\(.*\$request->|request\(`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for raw sql, got %d", len(findings))
	}
}

func TestRulesScanner_DebugStatements(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Debug.php"), []byte(`<?php
dd($var);
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-009",
			Title:   "Debug call",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `\b(dd|dump|var_dump)\s*\(`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for debug statement, got %d", len(findings))
	}
}

func TestRulesScanner_AppDebugEnv(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_DEBUG=true\n"), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-010",
			Title:   "APP_DEBUG true",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "env-files", Pattern: `^APP_DEBUG\s*=\s*true`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for APP_DEBUG, got %d", len(findings))
	}
}

func TestRulesScanner_EvalExec(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Exec.php"), []byte(`<?php
exec($request->cmd);
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-011",
			Title:   "Eval/exec input",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `\b(eval|exec|passthru|system)\s*\(.*(\$request->|\$_GET|\$_POST|request\()`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for eval/exec, got %d", len(findings))
	}
}

func TestRulesScanner_ComposerFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
  "require": {
    "php": "^8.0"
  }
}`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-012",
			Title:   "Composer php version",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "composer-files", Pattern: "\"php\": \"^8.0\""},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for composer file, got %d", len(findings))
	}
}

func TestRulesScanner_Parallel(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "A.php"), []byte(`<?php
// nothing
`), 0644)
	os.WriteFile(filepath.Join(dir, "app", "B.php"), []byte(`<?php
// nothing
`), 0644)

	rules := []config.RuleDefinition{}
	for i := 0; i < 20; i++ {
		rules = append(rules, config.RuleDefinition{
			ID:       fmt.Sprintf("PAR-%02d", i),
			Title:    "dummy",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{{Type: "contains", Target: "php-files", Pattern: "nothing"}},
		})
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, _ := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if len(findings) != 40 {
		t.Fatalf("expected 40 findings from parallel scan, got %d", len(findings))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings2, _ := s.Scan(ctx, pc, func(f models.Finding) {})
	if len(findings2) != 0 {
		t.Fatalf("expected 0 findings after canceled context, got %d", len(findings2))
	}
}

func TestSkipDir(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"vendor", true},
		{"node_modules", true},
		{".git", true},
		{"storage", true},
		{"app", false},
		{"src", false},
	}

	for _, tt := range tests {
		if got := skipDir(tt.name); got != tt.want {
			t.Errorf("skipDir(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
