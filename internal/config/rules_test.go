package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

	emptyWrappedYaml := `
meta:
  scope: "PHP native 8.0-8.4 (framework-agnostic baseline)"
rules:
`
	emptyWrappedPath := filepath.Join(tempDir, "empty-wrapped.yaml")
	if err := os.WriteFile(emptyWrappedPath, []byte(emptyWrappedYaml), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	rules, err = LoadRulesFromFile(emptyWrappedPath)
	if err != nil {
		t.Fatalf("expected no error loading empty wrapped yaml, got: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rule from empty wrapped yaml, got: %d", len(rules))
	}
}

type ruleWithFile struct {
	File string
	Rule RuleDefinition
}

func TestAllRulesYAMLAndRegexAreValid(t *testing.T) {
	all := mustLoadAllRules(t)
	for _, item := range all {
		rule := item.Rule
		for _, p := range rule.Patterns {
			if p.Type == "regex" || p.Type == "regex-multiline" || p.Type == "" {
				if p.Pattern != "" {
					if _, err := regexp.Compile(p.Pattern); err != nil {
						t.Errorf("invalid regex in %s rule %s: %v (pattern=%q)", item.File, rule.ID, err, p.Pattern)
					}
				}
				if p.ExcludePattern != "" {
					if _, err := regexp.Compile(p.ExcludePattern); err != nil {
						t.Errorf("invalid exclude regex in %s rule %s: %v (exclude_pattern=%q)", item.File, rule.ID, err, p.ExcludePattern)
					}
				}
			}
		}
	}
}

func TestAllRulesHaveUniqueIDs(t *testing.T) {
	all := mustLoadAllRules(t)
	seen := make(map[string]string, len(all))
	for _, item := range all {
		id := strings.TrimSpace(item.Rule.ID)
		if id == "" {
			t.Errorf("rule without id in %s", item.File)
			continue
		}
		if prev, exists := seen[id]; exists {
			t.Errorf("duplicate rule id %s found in %s and %s", id, prev, item.File)
			continue
		}
		seen[id] = item.File
	}
}

func TestRuleFilesDoNotContainDuplicateRuleSignatures(t *testing.T) {
	root := filepath.Join("..", "..", "rules")
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed walking rules dir: %v", err)
	}

	for _, file := range files {
		rules, err := LoadRulesFromFile(file)
		if err != nil {
			t.Fatalf("failed to parse rule file %s: %v", file, err)
		}

		seen := make(map[string]string, len(rules))
		for _, rule := range rules {
			sig := duplicateSignature(rule)
			if prev, ok := seen[sig]; ok {
				t.Errorf("duplicate rule signature in %s for rules %s and %s", file, prev, rule.ID)
				continue
			}
			seen[sig] = rule.ID
		}
	}
}

func TestAllRulesHaveMinimumComplianceMetadata(t *testing.T) {
	all := mustLoadAllRules(t)
	for _, item := range all {
		r := item.Rule
		hasCWE := strings.TrimSpace(r.CWE) != "" || hasTagPrefix(r.Tags, "cwe-")
		hasOWASP := strings.TrimSpace(r.OWASP) != "" || hasTagPrefix(r.Tags, "owasp-") || hasOWASPCategoryTag(r.Tags)
		hasRefs := len(r.References) > 0

		if !hasCWE || !hasOWASP || !hasRefs {
			t.Errorf("rule %s in %s missing compliance metadata (cwe=%t, owasp=%t, refs=%t)",
				r.ID, item.File, hasCWE, hasOWASP, hasRefs)
		}
	}
}

func TestCommonRulesDoNotUseFrameworkOnlyTargets(t *testing.T) {
	commonDir := filepath.Join("..", "..", "rules", "common")
	rules, err := LoadRulesFromDir(commonDir)
	if err != nil {
		t.Fatalf("failed to load common rules: %v", err)
	}

	for _, r := range rules {
		for _, p := range r.Patterns {
			target := strings.ToLower(strings.TrimSpace(p.Target))
			if target == "blade-files" || target == "twig-files" {
				t.Errorf("common rule %s must not use framework-only target %q", r.ID, p.Target)
			}
		}
	}
}

func TestCommonRulesArePHPNativeOnly(t *testing.T) {
	commonDir := filepath.Join("..", "..", "rules", "common")
	rules, err := LoadRulesFromDir(commonDir)
	if err != nil {
		t.Fatalf("failed to load common rules: %v", err)
	}

	disallowedTargets := map[string]bool{
		"routes-files":     true,
		"controller-files": true,
		"middleware-files": true,
		"model-files":      true,
		"request-files":    true,
		"service-files":    true,
		"blade-files":      true,
		"twig-files":       true,
	}
	disallowedTerms := []string{
		"laravel", "symfony", "wordpress", "codeigniter", "yii", "cakephp", "lumen",
		"eloquent", "artisan", "sanctum", "passport", "route::", "auth::", "gate::", "broadcast::", "resource::",
		"blade", "twig", "abort_unless", "abort_if", "abort(", "hash::", "view(", "view::", "db::",
	}

	for _, r := range rules {
		for _, p := range r.Patterns {
			target := strings.ToLower(strings.TrimSpace(p.Target))
			if disallowedTargets[target] {
				t.Errorf("common rule %s uses framework target %q", r.ID, p.Target)
			}

			patternBlob := strings.ToLower(p.Pattern + " " + p.ExcludePattern)
			for _, term := range disallowedTerms {
				if strings.Contains(patternBlob, term) {
					t.Errorf("common rule %s contains framework-specific pattern term %q", r.ID, term)
				}
			}
		}

		textBlob := strings.ToLower(strings.Join([]string{
			r.Title,
			r.Description,
			r.Remediation,
			strings.Join(r.Tags, " "),
			strings.Join(r.References, " "),
		}, " "))

		for _, term := range disallowedTerms {
			if strings.Contains(textBlob, term) {
				t.Errorf("common rule %s contains framework-specific text term %q", r.ID, term)
			}
		}
	}
}

func TestCommonScopeIsFrameworkAgnostic(t *testing.T) {
	commonDir := filepath.Join("..", "..", "rules", "common")
	files, err := os.ReadDir(commonDir)
	if err != nil {
		t.Fatalf("failed to read common rules dir: %v", err)
	}

	want := `scope: "PHP native 8.0-8.4 (framework-agnostic baseline)"`
	for _, f := range files {
		if f.IsDir() || (!strings.HasSuffix(f.Name(), ".yaml") && !strings.HasSuffix(f.Name(), ".yml")) {
			continue
		}
		path := filepath.Join(commonDir, f.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("common rule file %s must declare framework-agnostic scope", path)
		}
	}
}

func TestFrameworkRuleIDsMatchFrameworkPrefix(t *testing.T) {
	type fwCheck struct {
		file     string
		prefixes []string
	}

	checks := []fwCheck{
		{file: filepath.Join("..", "..", "rules", "symfony", "security.yaml"), prefixes: []string{"SYM-"}},
		{file: filepath.Join("..", "..", "rules", "wordpress", "security.yaml"), prefixes: []string{"WP-"}},
		{file: filepath.Join("..", "..", "rules", "codeigniter", "security.yaml"), prefixes: []string{"CI-"}},
		{file: filepath.Join("..", "..", "rules", "codeigniter4", "security.yaml"), prefixes: []string{"CI4-"}},
		{file: filepath.Join("..", "..", "rules", "yii2", "security.yaml"), prefixes: []string{"YII-"}},
		{file: filepath.Join("..", "..", "rules", "cakephp", "security.yaml"), prefixes: []string{"CAKE-"}},
		{
			file: filepath.Join("..", "..", "rules", "laravel", "security.yaml"),
			prefixes: []string{
				"LAR-", "ADV-", "CFG-", "SUPPLY-", "XSS-", "BIZ-", "DBG-",
			},
		},
	}

	for _, check := range checks {
		rules, err := LoadRulesFromFile(check.file)
		if err != nil {
			t.Fatalf("failed to load %s: %v", check.file, err)
		}

		for _, r := range rules {
			id := strings.ToUpper(strings.TrimSpace(r.ID))
			ok := false
			for _, p := range check.prefixes {
				if strings.HasPrefix(id, p) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("rule %s in %s has unexpected prefix, expected one of %v", r.ID, check.file, check.prefixes)
			}
		}
	}
}

func TestCommonRulesDoNotUseFrameworkIDPrefixes(t *testing.T) {
	commonDir := filepath.Join("..", "..", "rules", "common")
	rules, err := LoadRulesFromDir(commonDir)
	if err != nil {
		t.Fatalf("failed to load common rules: %v", err)
	}

	disallowed := []string{"LAR-", "SYM-", "WP-", "CI-", "CI4-", "YII-", "CAKE-"}
	for _, r := range rules {
		id := strings.ToUpper(strings.TrimSpace(r.ID))
		for _, p := range disallowed {
			if strings.HasPrefix(id, p) {
				t.Errorf("common rule %s uses framework-specific ID prefix %s", r.ID, p)
			}
		}
	}
}

func TestFrameworkTemplateTargetsAreScopedToRightFramework(t *testing.T) {
	all := mustLoadAllRules(t)
	for _, item := range all {
		file := filepath.ToSlash(item.File)
		rule := item.Rule
		for _, p := range rule.Patterns {
			target := strings.ToLower(strings.TrimSpace(p.Target))
			switch target {
			case "blade-files":
				if !strings.Contains(file, "/rules/laravel/") {
					t.Errorf("rule %s in %s uses blade-files but is outside laravel rules", rule.ID, item.File)
				}
			case "twig-files":
				if !strings.Contains(file, "/rules/symfony/") {
					t.Errorf("rule %s in %s uses twig-files but is outside symfony rules", rule.ID, item.File)
				}
			}
		}
	}
}

func TestFrameworkCategoryFilesExist(t *testing.T) {
	frameworkDirs := []string{
		filepath.Join("..", "..", "rules", "yii2"),
		filepath.Join("..", "..", "rules", "wordpress"),
		filepath.Join("..", "..", "rules", "symfony"),
		filepath.Join("..", "..", "rules", "laravel"),
		filepath.Join("..", "..", "rules", "codeigniter4"),
		filepath.Join("..", "..", "rules", "codeigniter"),
		filepath.Join("..", "..", "rules", "cakephp"),
	}
	categoryFiles := []string{
		"auth.yaml",
		"business-logic.yaml",
		"crypto.yaml",
		"debug.yaml",
		"deserialization.yaml",
		"file-upload.yaml",
		"injection.yaml",
		"jwt-security.yaml",
		"logging-monitoring.yaml",
		"middleware-security.yaml",
		"php-compatibility.yaml",
		"secrets.yaml",
		"security-config.yaml",
		"session-security.yaml",
		"ssrf.yaml",
		"supply-chain.yaml",
		"api-security.yaml",
	}

	for _, dir := range frameworkDirs {
		for _, file := range categoryFiles {
			path := filepath.Join(dir, file)
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("missing framework category file %s: %v", path, err)
				continue
			}
			if info.IsDir() {
				t.Errorf("expected file but found directory: %s", path)
			}
		}
	}
}

func TestFrameworkCategoryFilesHaveAtLeastTwoRules(t *testing.T) {
	frameworkDirs := []string{
		filepath.Join("..", "..", "rules", "yii2"),
		filepath.Join("..", "..", "rules", "wordpress"),
		filepath.Join("..", "..", "rules", "symfony"),
		filepath.Join("..", "..", "rules", "laravel"),
		filepath.Join("..", "..", "rules", "codeigniter4"),
		filepath.Join("..", "..", "rules", "codeigniter"),
		filepath.Join("..", "..", "rules", "cakephp"),
	}
	categoryFiles := []string{
		"auth.yaml",
		"business-logic.yaml",
		"crypto.yaml",
		"debug.yaml",
		"deserialization.yaml",
		"file-upload.yaml",
		"injection.yaml",
		"jwt-security.yaml",
		"logging-monitoring.yaml",
		"middleware-security.yaml",
		"php-compatibility.yaml",
		"secrets.yaml",
		"security-config.yaml",
		"session-security.yaml",
		"ssrf.yaml",
		"supply-chain.yaml",
		"api-security.yaml",
	}

	for _, dir := range frameworkDirs {
		for _, file := range categoryFiles {
			path := filepath.Join(dir, file)
			rules, err := LoadRulesFromFile(path)
			if err != nil {
				t.Errorf("failed to parse framework category file %s: %v", path, err)
				continue
			}
			if len(rules) < 2 {
				t.Errorf("framework category file %s should contain at least 2 rules, got %d", path, len(rules))
			}
		}
	}
}

func TestAllRulesHaveConfidence(t *testing.T) {
	all := mustLoadAllRules(t)
	allowed := map[string]bool{
		"low": true, "medium": true, "high": true,
	}
	for _, item := range all {
		c := strings.ToLower(strings.TrimSpace(item.Rule.Confidence))
		if c == "" {
			t.Errorf("rule %s in %s missing confidence", item.Rule.ID, item.File)
			continue
		}
		if !allowed[c] {
			t.Errorf("rule %s in %s has invalid confidence %q", item.Rule.ID, item.File, item.Rule.Confidence)
		}
	}
}

func TestRulesDoNotContainEncodingArtifacts(t *testing.T) {
	root := filepath.Join("..", "..", "rules")
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed walking rules dir: %v", err)
	}

	badMarkers := []string{"ï¿½", "\uFFFD"}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		content := string(data)
		for _, bad := range badMarkers {
			if strings.Contains(content, bad) {
				t.Errorf("encoding artifact %q found in %s", bad, file)
			}
		}
	}
}

func mustLoadAllRules(t *testing.T) []ruleWithFile {
	t.Helper()

	root := filepath.Join("..", "..", "rules")
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed walking rules dir: %v", err)
	}

	all := make([]ruleWithFile, 0, 256)
	for _, file := range files {
		rules, err := LoadRulesFromFile(file)
		if err != nil {
			t.Fatalf("failed to parse rule file %s: %v", file, err)
		}
		for _, r := range rules {
			all = append(all, ruleWithFile{File: file, Rule: r})
		}
	}

	return all
}

func hasTagPrefix(tags []string, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tag)), prefix) {
			return true
		}
	}
	return false
}

func hasOWASPCategoryTag(tags []string) bool {
	for _, tag := range tags {
		t := strings.ToUpper(strings.TrimSpace(tag))
		if strings.HasPrefix(t, "A0") || strings.HasPrefix(t, "A1") {
			return true
		}
	}
	return false
}

func duplicateSignature(rule RuleDefinition) string {
	parts := make([]string, 0, len(rule.Patterns))
	for _, p := range rule.Patterns {
		parts = append(parts, strings.Join([]string{
			strings.ToLower(strings.TrimSpace(p.Type)),
			strings.ToLower(strings.TrimSpace(p.Target)),
			strings.TrimSpace(p.Pattern),
			strings.ToLower(strings.TrimSpace(p.Scope)),
			strings.TrimSpace(p.ExcludePattern),
			boolString(p.Negative),
		}, "|"))
	}
	sort.Strings(parts)

	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(rule.Category)),
		strings.ToLower(strings.TrimSpace(rule.Condition)),
		strings.Join(parts, "||"),
	}, "###")
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
