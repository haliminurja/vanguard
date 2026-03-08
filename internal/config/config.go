package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Severity  string          `yaml:"severity"`
	Output    OutputConfig    `yaml:"output"`
	Scanners  ScannersConfig  `yaml:"scanners"`
	Providers ProvidersConfig `yaml:"providers"`
	Ignore    IgnoreConfig    `yaml:"ignore"`
}
type OutputConfig struct {
	Formats []string `yaml:"formats"`
	Dir     string   `yaml:"dir"`
}
type ScannersConfig struct {
	Enable      []string `yaml:"enable"`
	Disable     []string `yaml:"disable"`
	RuleEnable  []string `yaml:"rule_enable"`
	RuleDisable []string `yaml:"rule_disable"`
	IgnoreDirs  []string `yaml:"ignore_dirs"`
}
type ProvidersConfig struct {
	GitDepth int `yaml:"git_depth"`
}
type IgnoreConfig struct {
	Paths []string `yaml:"paths"`
	Rules []string `yaml:"rules"`
}

func (c *Config) Merge(other *Config) {
	if other == nil {
		return
	}
	if other.Severity != "" {
		c.Severity = other.Severity
	}
	if len(other.Output.Formats) > 0 {
		c.Output.Formats = other.Output.Formats
	}
	if other.Output.Dir != "" {
		c.Output.Dir = other.Output.Dir
	}
	if len(other.Scanners.Enable) > 0 {
		c.Scanners.Enable = append(c.Scanners.Enable, other.Scanners.Enable...)
	}
	if len(other.Scanners.Disable) > 0 {
		c.Scanners.Disable = append(c.Scanners.Disable, other.Scanners.Disable...)
	}
	if len(other.Scanners.RuleEnable) > 0 {
		c.Scanners.RuleEnable = append(c.Scanners.RuleEnable, other.Scanners.RuleEnable...)
	}
	if len(other.Scanners.RuleDisable) > 0 {
		c.Scanners.RuleDisable = append(c.Scanners.RuleDisable, other.Scanners.RuleDisable...)
	}
	if len(other.Scanners.IgnoreDirs) > 0 {
		c.Scanners.IgnoreDirs = append(c.Scanners.IgnoreDirs, other.Scanners.IgnoreDirs...)
	}
	if other.Providers.GitDepth > 0 {
		c.Providers.GitDepth = other.Providers.GitDepth
	}
	if len(other.Ignore.Paths) > 0 {
		c.Ignore.Paths = append(c.Ignore.Paths, other.Ignore.Paths...)
	}
	if len(other.Ignore.Rules) > 0 {
		c.Ignore.Rules = append(c.Ignore.Rules, other.Ignore.Rules...)
	}
}

func (c *Config) Validate() error {
	validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[c.Severity] {
		return fmt.Errorf("invalid severity: %s", c.Severity)
	}

	if c.Providers.GitDepth < 1 {
		return fmt.Errorf("git_depth must be at least 1")
	}

	validFormats := map[string]bool{"json": true, "sarif": true, "html": true, "markdown": true, "tui": true}
	for _, f := range c.Output.Formats {
		if !validFormats[f] {
			return fmt.Errorf("invalid output format: %s", f)
		}
	}

	return nil
}

func Default() *Config {
	return &Config{
		Severity: "info",
		Output: OutputConfig{
			Formats: []string{"json", "sarif", "html", "markdown"},
			Dir:     ".",
		},
		Scanners: ScannersConfig{},
		Providers: ProvidersConfig{
			GitDepth: 1,
		},
	}
}
func Load(projectRoot string) (*Config, error) {
	cfg := Default()

	globalPath, err := FilePath("config.yaml")
	if err == nil {
		if data, err := os.ReadFile(globalPath); err == nil {
			_ = yaml.Unmarshal(data, cfg)
		}
	}

	projectConfigs := []string{
		filepath.Join(projectRoot, "vanguard.yaml"),
		filepath.Join(projectRoot, ".vanguard.yaml"),
	}

	for _, p := range projectConfigs {
		if data, err := os.ReadFile(p); err == nil {
			var projectCfg Config
			if err := yaml.Unmarshal(data, &projectCfg); err == nil {
				cfg.Merge(&projectCfg)
				break
			}
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}
func Save(cfg *Config) error {
	if err := EnsureDir(); err != nil {
		return err
	}

	path, err := FilePath("config.yaml")
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	header := []byte("# Vanguard Configuration\n")
	return os.WriteFile(path, append(header, data...), 0600)
}
