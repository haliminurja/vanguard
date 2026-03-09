package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	CWE         string       `yaml:"cwe"`
	OWASP       string       `yaml:"owasp"`
	CVSSv3      CVSSv3Def    `yaml:"cvss_v3"`
	Confidence  string       `yaml:"confidence"`
	Condition   string       `yaml:"condition"`
	Patterns    []PatternDef `yaml:"patterns"`
	Remediation string       `yaml:"remediation"`
	References  []string     `yaml:"references"`
}

type CVSSv3Def struct {
	Score  float64 `yaml:"score"`
	Vector string  `yaml:"vector"`
}

type PatternDef struct {
	Type           string `yaml:"type"`
	Target         string `yaml:"target"`
	Pattern        string `yaml:"pattern"`
	Scope          string `yaml:"scope"`
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
		return normalizeAndValidateRules(wrapped.Rules, filePath)
	}

	var rules []RuleDefinition
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return normalizeAndValidateRules(rules, filePath)
}

func isYAMLFile(name string) bool {
	return filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml"
}

func normalizeAndValidateRules(rules []RuleDefinition, filePath string) ([]RuleDefinition, error) {
	normalized := make([]RuleDefinition, 0, len(rules))

	for _, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Title = strings.TrimSpace(rule.Title)
		rule.Severity = strings.TrimSpace(rule.Severity)
		rule.Category = strings.TrimSpace(rule.Category)

		condition := strings.ToLower(strings.TrimSpace(rule.Condition))
		if condition == "" {
			rule.Condition = "any"
		} else {
			if condition != "any" && condition != "all" {
				return nil, fmt.Errorf("%s: invalid condition %q for rule %q", filePath, rule.Condition, rule.ID)
			}
			rule.Condition = condition
		}

		for j := range rule.Patterns {
			pat := &rule.Patterns[j]
			pat.Type = strings.ToLower(strings.TrimSpace(pat.Type))
			pat.Target = strings.TrimSpace(pat.Target)
			pat.Scope = strings.ToLower(strings.TrimSpace(pat.Scope))

			if pat.Scope != "" && pat.Scope != "file" && pat.Scope != "project" && pat.Scope != "global" {
				return nil, fmt.Errorf("%s: invalid scope %q in rule %q pattern #%d", filePath, pat.Scope, rule.ID, j+1)
			}

			switch pat.Type {
			case "regex", "regex-multiline":
				if strings.TrimSpace(pat.Pattern) == "" {
					return nil, fmt.Errorf("%s: empty regex pattern in rule %q pattern #%d", filePath, rule.ID, j+1)
				}
				if _, err := regexp.Compile(pat.Pattern); err != nil {
					return nil, fmt.Errorf("%s: invalid regex in rule %q pattern #%d: %w", filePath, rule.ID, j+1, err)
				}
			case "contains", "file-exists", "entropy":
				// Valid pattern types.
			default:
				return nil, fmt.Errorf("%s: unsupported pattern type %q in rule %q pattern #%d", filePath, pat.Type, rule.ID, j+1)
			}

			if strings.TrimSpace(pat.ExcludePattern) != "" {
				if _, err := regexp.Compile(pat.ExcludePattern); err != nil {
					return nil, fmt.Errorf("%s: invalid exclude_pattern in rule %q pattern #%d: %w", filePath, rule.ID, j+1, err)
				}
			}
		}

		normalized = append(normalized, rule)
	}

	return normalized, nil
}
