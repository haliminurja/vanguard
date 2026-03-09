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

func TestRulesScanner_TargetAny(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
  "minimum-stability": "dev"
}`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-ANY-001",
			Title:   "Minimum stability dev",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "any", Pattern: `"minimum-stability"\s*:\s*"dev"`},
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
		t.Fatalf("expected 1 finding for target any, got %d", len(findings))
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

func TestRulesScanner_RegexMatchesAcrossLines(t *testing.T) {
	dir := t.TempDir()
	controllerDir := filepath.Join(dir, "app", "Http", "Controllers")
	os.MkdirAll(controllerDir, 0755)
	os.WriteFile(filepath.Join(controllerDir, "UserController.php"), []byte(`<?php
class UserController
{
    public function update($request, $user)
    {
        $user->update($request->all());
    }
}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-REGEX-MULTI-LINE-001",
			Title:   "Controller CRUD without authorization check",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{
					Type:    "regex",
					Target:  "controller-files",
					Pattern: `public\s+function\s+update\s*\([^)]*\)\s*\{[^}]*->update\s*\(`,
				},
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
		t.Fatalf("expected 1 finding for multi-line regex rule, got %d", len(findings))
	}
	if findings[0].Line != 4 {
		t.Fatalf("expected finding line 4, got %d", findings[0].Line)
	}
}

func TestRulesScanner_RegexSupportsEmbeddedNewlines(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	os.MkdirAll(configDir, 0755)
	os.WriteFile(filepath.Join(configDir, "packages.yaml"), []byte(`framework:
  something: true
web_profiler:
  toolbar: true
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-REGEX-MULTI-LINE-002",
			Title:   "Profiler enabled",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{
					Type:    "regex",
					Target:  "config-files",
					Pattern: `web_profiler:\s*\n\s*toolbar:\s*true`,
				},
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
		t.Fatalf("expected 1 finding for regex with embedded newline, got %d", len(findings))
	}
	if findings[0].Line != 3 {
		t.Fatalf("expected finding line 3, got %d", findings[0].Line)
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

func TestRulesScanner_PHPFilesIgnoreBladeTemplates(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "resources", "views"), 0755)
	os.WriteFile(filepath.Join(dir, "resources", "views", "token.blade.php"), []byte(`{{ JWT::encode($payload, $key, 'HS256') }}`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-PHP-IGNORE-BLADE",
			Title:   "JWT usage in PHP source",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `JWT::encode\s*\(`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings from blade template under php-files target, got %d", len(findings))
	}
}

func TestRulesScanner_BuildFindingIncludesComplianceMetadata(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Crypto.php"), []byte(`<?php
$password = "hardcoded123";
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-META-001",
			Title:    "Dangerous eval",
			Severity: "critical",
			Category: "RCE",
			Enabled:  boolPtr(true),
			Tags:     []string{"security", "cwe-94", "owasp-a03"},
			CWE:      "CWE-94",
			OWASP:    "A03:2021",
			CVSSv3:   config.CVSSv3Def{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
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

	f := findings[0]
	if f.CWE != "CWE-94" {
		t.Fatalf("expected CWE-94, got %q", f.CWE)
	}
	if f.OWASP != "A03:2021" {
		t.Fatalf("expected A03:2021, got %q", f.OWASP)
	}
	if f.CVSSScore != 9.8 {
		t.Fatalf("expected CVSS score 9.8, got %v", f.CVSSScore)
	}
	if f.CVSSVector == "" {
		t.Fatal("expected CVSS vector to be populated")
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

func TestRulesScanner_ConditionAllReturnsSingleFinding(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Auth.php"), []byte(`<?php
if (Auth::attempt($credentials)) {
    return true;
}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:        "TEST-ALL-001",
			Title:     "Missing login failure logging",
			Severity:  "medium",
			Enabled:   boolPtr(true),
			Condition: "all",
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "php-files", Pattern: "Auth::attempt("},
				{Type: "regex", Target: "php-files", Pattern: `Log::(warning|error|info)`, Negative: true},
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
		t.Fatalf("expected 1 finding for condition all, got %d", len(findings))
	}
	if findings[0].Line != 2 {
		t.Fatalf("expected anchored line 2, got %d", findings[0].Line)
	}
}

func TestRulesScanner_ProjectScopeNegativeMissing(t *testing.T) {
	dir := t.TempDir()
	middlewareDir := filepath.Join(dir, "app", "Http", "Middleware")
	os.MkdirAll(middlewareDir, 0755)
	os.WriteFile(filepath.Join(middlewareDir, "A.php"), []byte(`<?php
class A {}
`), 0644)
	os.WriteFile(filepath.Join(middlewareDir, "B.php"), []byte(`<?php
class B {}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-SCOPE-001",
			Title:   "Missing security header",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "middleware-files", Scope: "project", Pattern: "X-Frame-Options", Negative: true},
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
		t.Fatalf("expected 1 project-scope finding, got %d", len(findings))
	}
	if findings[0].File != "app/Http/Middleware" {
		t.Fatalf("expected aggregated location app/Http/Middleware, got %q", findings[0].File)
	}
	if findings[0].Line != 0 {
		t.Fatalf("expected line 0 for project-scope finding, got %d", findings[0].Line)
	}
}

func TestRulesScanner_ProjectScopeNegativeSatisfied(t *testing.T) {
	dir := t.TempDir()
	middlewareDir := filepath.Join(dir, "app", "Http", "Middleware")
	os.MkdirAll(middlewareDir, 0755)
	os.WriteFile(filepath.Join(middlewareDir, "SecurityHeaders.php"), []byte(`<?php
$response->headers->set('X-Frame-Options', 'SAMEORIGIN');
`), 0644)
	os.WriteFile(filepath.Join(middlewareDir, "Other.php"), []byte(`<?php
class Other {}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-SCOPE-002",
			Title:   "Missing security header",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "contains", Target: "middleware-files", Scope: "project", Pattern: "X-Frame-Options", Negative: true},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when project-scope header exists, got %d", len(findings))
	}
}

func TestRulesScanner_CommentedCodeIgnored(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Debug.php"), []byte(`<?php
// exec($_GET['cmd']);
# system($_POST['x']);
/* passthru($_REQUEST['run']); */
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-COMMENT-001",
			Title:   "Dangerous command execution",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `\b(exec|system|passthru)\s*\(`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for commented code, got %d", len(findings))
	}
}

func TestRulesScanner_MultilineCommentBodyIgnored(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Commented.php"), []byte(`<?php
/*
exec($_GET['cmd']);
*/
$safe = true;
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-COMMENT-002",
			Title:   "Dangerous command execution",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `\b(exec|system|passthru)\s*\(`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for multiline commented code, got %d", len(findings))
	}
}

func TestRulesScanner_MultiTargetPatternIsolation(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Service.php"), []byte(`<?php
Route::get('/token/{token}', fn () => 'ok');
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-MULTI-001",
			Title:   "Token in URL route pattern",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "routes-files", Pattern: `Route::(get|any)\s*\([^)]*\{token\}`},
				{Type: "regex", Target: "php-files", Pattern: `\$request->query\s*\(\s*["']?token["']?\s*\)`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings because routes-target pattern must not run on php-files fallback, got %d", len(findings))
	}
}

func TestRulesScanner_ExcludePatternUsesContextWindow(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "HttpClient.php"), []byte(`<?php
$allowed = parse_url($request->url, PHP_URL_HOST);
curl_setopt($ch, CURLOPT_URL, $request->url);
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-EXCLUDE-001",
			Title:   "Potential SSRF",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{
					Type:           "regex",
					Target:         "php-files",
					Pattern:        `curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$`,
					ExcludePattern: `parse_url`,
				},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings due nearby parse_url exclusion, got %d", len(findings))
	}
}

func TestRulesScanner_TargetAnySkipsEngineRulesDirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "rules"), 0755)
	os.WriteFile(filepath.Join(dir, "rules", "sample.yaml"), []byte(`{
  "minimum-stability": "dev"
}`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-ANY-SKIP-001",
			Title:   "Minimum stability dev",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "any", Scope: "project", Pattern: `"minimum-stability"\s*:\s*"dev"`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings because root rules dir should be ignored by target:any, got %d", len(findings))
	}
}

func TestRulesScanner_JSFilesTargetScansSrcDirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "src"), 0755)
	os.WriteFile(filepath.Join(dir, "src", "main.ts"), []byte(`const url = userInputUrl;
fetch(url);
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-JS-001",
			Title:   "Dynamic outbound request",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "js-files", Pattern: `fetch\s*\(`},
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
		t.Fatalf("expected 1 finding for src/main.ts js-files scan, got %d", len(findings))
	}
}

func TestRulesScanner_RoutesTargetSupportsAppConfigRoutes(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app", "Config"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "Config", "Routes.php"), []byte(`<?php
$routes->add('/admin', 'Admin::index');
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-ROUTES-001",
			Title:   "Admin route exists",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "routes-files", Pattern: `admin`},
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
		t.Fatalf("expected 1 finding for app/Config/Routes.php target, got %d", len(findings))
	}
}

func TestRulesScanner_ModelFilesSupportCakePHPLayout(t *testing.T) {
	dir := t.TempDir()
	entityDir := filepath.Join(dir, "src", "Model", "Entity")
	os.MkdirAll(entityDir, 0755)
	os.WriteFile(filepath.Join(entityDir, "User.php"), []byte(`<?php
class User
{
    protected $_accessible = ['*' => true];
}
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-MODEL-CAKE-001",
			Title:   "Cake model mass assignment",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "model-files", Pattern: `\$_accessible\s*=\s*\[[^\]]*['"]\*['"]\s*=>\s*true`},
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
		t.Fatalf("expected 1 finding for CakePHP src/Model/Entity target, got %d", len(findings))
	}
	if filepath.ToSlash(findings[0].File) != "src/Model/Entity/User.php" {
		t.Fatalf("expected finding in src/Model/Entity/User.php, got %q", findings[0].File)
	}
}

func TestRulesScanner_BinaryFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	// Includes NULL bytes to emulate binary payload disguised as .php file.
	os.WriteFile(filepath.Join(dir, "app", "Binary.php"), []byte{0x00, 0x01, 0x02, 0x03, 0x04}, 0644)

	rules := []config.RuleDefinition{
		{
			ID:      "TEST-BIN-001",
			Title:   "Any content",
			Enabled: boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: `.`},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}
	findings, err := s.Scan(context.Background(), pc, func(f models.Finding) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for binary file, got %d", len(findings))
	}
}

func TestRulesScanner_Parallel(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)
	os.WriteFile(filepath.Join(dir, "app", "A.php"), []byte(`<?php
$a = "nothing";
`), 0644)
	os.WriteFile(filepath.Join(dir, "app", "B.php"), []byte(`<?php
$b = "nothing";
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

func TestRulesScanner_Entropy(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "app"), 0755)

	// A standard string shouldn't trigger high entropy (e.g. low randomness)
	os.WriteFile(filepath.Join(dir, "app", "Normal.php"), []byte(`<?php
$token = "just_a_normal_token_string";
`), 0644)

	// A highly random base64/hex string should trigger the entropy scanner
	os.WriteFile(filepath.Join(dir, "app", "HighEntropy.php"), []byte(`<?php
$secret = "z8x9C2vB5nN1mQ7wW3eE4rR6tT8yY0uI5oO9pP3aA8sS7dD6fF4gG2hH1jJ5kK0lL";
`), 0644)

	rules := []config.RuleDefinition{
		{
			ID:       "TEST-ENT-01",
			Title:    "High Entropy Secret Detected",
			Severity: "high",
			Enabled:  boolPtr(true),
			Patterns: []config.PatternDef{
				{Type: "entropy", Target: "php-files", Pattern: "4.5"},
			},
		},
	}

	s := NewRulesScanner(rules)
	pc := models.ProjectContext{RootPath: dir}

	var findings []models.Finding
	_, err := s.Scan(context.Background(), pc, func(f models.Finding) {
		findings = append(findings, f)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for high entropy, got %d", len(findings))
	}

	if filepath.Base(findings[0].File) != "HighEntropy.php" {
		t.Errorf("expected finding in HighEntropy.php, got %s", findings[0].File)
	}
}
