package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type RuleDefinition struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Category    string `yaml:"category"`

	Enabled     *bool        `yaml:"enabled"`
	Tags        []string     `yaml:"tags"`
	Confidence  string       `yaml:"confidence"`
	Condition   string       `yaml:"condition"`
	Patterns    []PatternDef `yaml:"patterns"`
	Remediation string       `yaml:"remediation"`
	References  []string     `yaml:"references"`
}

type PatternDef struct {
	Type           string `yaml:"type"`
	Target         string `yaml:"target"`
	Pattern        string `yaml:"pattern"`
	Negative       bool   `yaml:"negative"`
	ExcludePattern string `yaml:"exclude_pattern"`
}

type rulesFile struct {
	Rules []RuleDefinition `yaml:"rules"`
}

func LoadRulesFromDir(dir string) ([]RuleDefinition, error) {
	var allRules []RuleDefinition

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return allRules, nil
		}
		return nil, fmt.Errorf("reading rules directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		rules, err := LoadRulesFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("loading rules from %s: %w", filePath, err)
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func LoadRulesFromFile(filePath string) ([]RuleDefinition, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var wrapped rulesFile
	if err := yaml.Unmarshal(data, &wrapped); err == nil && len(wrapped.Rules) > 0 {
		return wrapped.Rules, nil
	}

	var rules []RuleDefinition
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return rules, nil
}

func isYAMLFile(name string) bool {
	return filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml"
}
