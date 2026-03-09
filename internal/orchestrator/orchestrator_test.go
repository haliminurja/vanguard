package orchestrator

import (
	"strings"
	"testing"

	"vanguard/internal/config"
)

func TestFilterRules_EnableDisable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scanners.RuleEnable = []string{"R1", "R3"}
	cfg.Scanners.RuleDisable = []string{"R2"}
	o := &Orchestrator{cfg: cfg}

	rules := []config.RuleDefinition{
		{ID: "R1"},
		{ID: "R2"},
		{ID: "R3"},
		{ID: "R4"},
	}

	filtered := o.filterRules(rules)

	if len(filtered) != 2 {
		t.Fatalf("expected 2 rules after filtering, got %d", len(filtered))
	}
	ids := map[string]bool{}
	for _, r := range filtered {
		ids[r.ID] = true
	}
	if !ids["R1"] || !ids["R3"] {
		t.Errorf("filtered rules missing expected IDs: %v", ids)
	}
}

func TestFilterRulesByFramework_GenericProjectSkipsFrameworkSpecificRules(t *testing.T) {
	rules := []config.RuleDefinition{
		{
			ID:    "GEN-001",
			Tags:  []string{"security", "owasp-a03"},
			Title: "Generic SQL rule",
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: "exec\\("},
			},
		},
		{
			ID:    "LAR-001",
			Tags:  []string{"laravel", "blade"},
			Title: "Blade unsafe output",
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "blade-files", Pattern: "\\{!!"},
			},
		},
	}

	filtered := filterRulesByFramework(rules, "")
	if len(filtered) != 1 {
		t.Fatalf("expected only generic rule for framework-agnostic project, got %d", len(filtered))
	}
	if filtered[0].ID != "GEN-001" {
		t.Fatalf("expected GEN-001 to remain, got %s", filtered[0].ID)
	}
}

func TestFilterRulesByFramework_LaravelProjectKeepsLaravelRules(t *testing.T) {
	rules := []config.RuleDefinition{
		{
			ID:    "GEN-001",
			Tags:  []string{"security", "owasp-a03"},
			Title: "Generic SQL rule",
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "php-files", Pattern: "exec\\("},
			},
		},
		{
			ID:    "LAR-001",
			Tags:  []string{"laravel", "blade"},
			Title: "Blade unsafe output",
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "blade-files", Pattern: "\\{!!"},
			},
		},
		{
			ID:    "SYM-001",
			Tags:  []string{"symfony", "twig"},
			Title: "Twig unsafe output",
			Patterns: []config.PatternDef{
				{Type: "regex", Target: "twig-files", Pattern: "\\|raw"},
			},
		},
	}

	filtered := filterRulesByFramework(rules, "laravel")
	if len(filtered) != 2 {
		t.Fatalf("expected generic + laravel rules, got %d", len(filtered))
	}

	seen := map[string]bool{}
	for _, rule := range filtered {
		seen[rule.ID] = true
	}
	if !seen["GEN-001"] || !seen["LAR-001"] || seen["SYM-001"] {
		t.Fatalf("unexpected filter result: %+v", seen)
	}
}

func TestFilterRulesByFramework_AllFrameworkPrefixes(t *testing.T) {
	rules := []config.RuleDefinition{
		{ID: "GEN-001", Title: "Generic", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "exec\\("}}},
		{ID: "LAR-001", Title: "Laravel", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "laravel"}}},
		{ID: "SYM-001", Title: "Symfony", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "symfony"}}},
		{ID: "WP-001", Title: "WordPress", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "wordpress"}}},
		{ID: "CI-001", Title: "CodeIgniter", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "ci3"}}},
		{ID: "CI4-001", Title: "CodeIgniter4", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "ci4"}}},
		{ID: "YII-001", Title: "Yii2", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "yii"}}},
		{ID: "CAKE-001", Title: "CakePHP", Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: "cake"}}},
	}

	tests := []struct {
		framework string
		wantIDs   []string
	}{
		{framework: "laravel", wantIDs: []string{"GEN-001", "LAR-001"}},
		{framework: "symfony", wantIDs: []string{"GEN-001", "SYM-001"}},
		{framework: "wordpress", wantIDs: []string{"GEN-001", "WP-001"}},
		{framework: "codeigniter", wantIDs: []string{"GEN-001", "CI-001", "CI4-001"}},
		{framework: "codeigniter4", wantIDs: []string{"GEN-001", "CI-001", "CI4-001"}},
		{framework: "yii2", wantIDs: []string{"GEN-001", "YII-001"}},
		{framework: "cakephp", wantIDs: []string{"GEN-001", "CAKE-001"}},
	}

	for _, tt := range tests {
		t.Run(tt.framework, func(t *testing.T) {
			filtered := filterRulesByFramework(rules, tt.framework)
			seen := map[string]bool{}
			for _, rule := range filtered {
				seen[rule.ID] = true
			}

			for _, id := range tt.wantIDs {
				if !seen[id] {
					t.Fatalf("framework %s should include %s, got %+v", tt.framework, id, seen)
				}
			}

			for id := range seen {
				want := false
				for _, expected := range tt.wantIDs {
					if id == expected {
						want = true
						break
					}
				}
				if !want {
					t.Fatalf("framework %s unexpectedly included %s", tt.framework, id)
				}
			}
		})
	}
}

func TestInferRuleFrameworkFromIDPrefix(t *testing.T) {
	tests := map[string]string{
		"LAR-100":  "laravel",
		"SYM-100":  "symfony",
		"WP-100":   "wordpress",
		"CI-100":   "codeigniter",
		"CI4-100":  "codeigniter4",
		"YII-100":  "yii2",
		"CAKE-100": "cakephp",
	}

	for id, want := range tests {
		t.Run(id, func(t *testing.T) {
			got := inferRuleFramework(config.RuleDefinition{
				ID:       id,
				Title:    "test",
				Patterns: []config.PatternDef{{Type: "regex", Target: "php-files", Pattern: strings.ToLower(id)}},
			})
			if got != want {
				t.Fatalf("inferRuleFramework(%s)=%s, want %s", id, got, want)
			}
		})
	}
}
