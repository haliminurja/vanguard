package orchestrator

import (
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
