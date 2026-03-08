package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"vanguard/internal/models"
)

type FrameworkResolver struct{}

func NewFrameworkResolver() *FrameworkResolver {
	return &FrameworkResolver{}
}

func (r *FrameworkResolver) Name() string  { return "framework" }
func (r *FrameworkResolver) Priority() int { return 10 }

func (r *FrameworkResolver) Resolve(_ context.Context, root string, pc *models.ProjectContext) error {
	pc.RootPath = root

	r.resolveComposer(root, pc)
	r.resolvePackageJSON(root, pc)
	r.resolveFileBasedFrameworks(root, pc)
	r.resolveGenericPHP(root, pc)
	r.resolveEnv(root, pc)

	return nil
}

func (r *FrameworkResolver) resolveComposer(root string, pc *models.ProjectContext) {
	data, err := os.ReadFile(filepath.Join(root, "composer.json"))
	if err != nil {
		return
	}

	var composer struct {
		Name    string            `json:"name"`
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return
	}

	if composer.Name != "" && pc.ProjectName == "" {
		pc.ProjectName = composer.Name
	}
	if pc.ComposerDeps == nil {
		pc.ComposerDeps = make(map[string]string)
	}
	for pkg, ver := range composer.Require {
		pc.ComposerDeps[pkg] = ver
	}

	frameworkMap := map[string]string{
		"laravel/framework":                 "laravel",
		"laravel/lumen-framework":           "lumen",
		"symfony/framework-bundle":          "symfony",
		"yiisoft/yii2":                      "yii2",
		"slim/slim":                         "slim",
		"cakephp/cakephp":                   "cakephp",
		"codeigniter4/framework":            "codeigniter4",
		"laminas/laminas-mvc":               "laminas",
		"phalcon/cphalcon":                  "phalcon",
		"drupal/core":                       "drupal",
		"joomla/joomla-cms":                 "joomla",
		"magento/product-community-edition": "magento",
	}

	for pkg, framework := range frameworkMap {
		if v, ok := composer.Require[pkg]; ok {
			pc.FrameworkType = framework
			if framework == "laravel" {
				pc.LaravelVersion = v
			}
			break
		}
	}

	if v, ok := composer.Require["php"]; ok {
		pc.PHPVersion = v
	}
}

func (r *FrameworkResolver) resolvePackageJSON(root string, pc *models.ProjectContext) {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return
	}

	var pkgJSON struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkgJSON); err != nil {
		return
	}

	if pkgJSON.Name != "" && pc.ProjectName == "" {
		pc.ProjectName = pkgJSON.Name
	}

	deps := make(map[string]string)
	for k, v := range pkgJSON.Dependencies {
		deps[k] = v
	}
	for k, v := range pkgJSON.DevDependencies {
		deps[k] = v
	}

	if _, ok := deps["next"]; ok {
		pc.FrameworkType = "nextjs"
	} else if _, ok := deps["express"]; ok {
		pc.FrameworkType = "express"
	} else if _, ok := deps["@angular/core"]; ok {
		pc.FrameworkType = "angular"
	} else if _, ok := deps["react"]; ok {
		pc.FrameworkType = "react"
	} else if _, ok := deps["vue"]; ok {
		pc.FrameworkType = "vue"
	}
}

func (r *FrameworkResolver) resolveFileBasedFrameworks(root string, pc *models.ProjectContext) {
	if pc.FrameworkType != "" {
		return
	}

	if _, err := os.Stat(filepath.Join(root, "artisan")); err == nil {
		pc.FrameworkType = "laravel"
		return
	}

	if _, err := os.Stat(filepath.Join(root, "spark")); err == nil {
		pc.FrameworkType = "codeigniter4"
		return
	}
	if _, err := os.Stat(filepath.Join(root, "app", "Config", "App.php")); err == nil {
		pc.FrameworkType = "codeigniter4"
		return
	}

	if _, err := os.Stat(filepath.Join(root, "application", "config", "config.php")); err == nil {
		pc.FrameworkType = "codeigniter3"
		return
	}

	if _, err := os.Stat(filepath.Join(root, "system", "core", "Common.php")); err == nil {
		if _, err := os.Stat(filepath.Join(root, "application", "core")); err == nil {
			pc.FrameworkType = "codeigniter2"
			return
		}
	}

	if _, err := os.Stat(filepath.Join(root, "wp-config.php")); err == nil {
		pc.FrameworkType = "wordpress"
		return
	}
}

func (r *FrameworkResolver) resolveGenericPHP(root string, pc *models.ProjectContext) {
	if pc.FrameworkType != "" {
		return
	}

	isPHP := false
	if _, err := os.Stat(filepath.Join(root, "index.php")); err == nil {
		isPHP = true
	} else {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
					isPHP = true
					break
				}
			}
		}
	}

	if isPHP {
		pc.FrameworkType = "php-generic"
	}
}

func (r *FrameworkResolver) resolveEnv(root string, pc *models.ProjectContext) {
	envVars := parseEnvFile(filepath.Join(root, ".env"))

	if name, ok := envVars["APP_NAME"]; ok && pc.ProjectName == "" {
		pc.ProjectName = name
	}
	if pc.EnvVariables == nil {
		pc.EnvVariables = make(map[string]string)
	}
	for k := range envVars {
		pc.EnvVariables[k] = "***"
	}

	if pc.FrameworkType == "laravel" {
		configDir := filepath.Join(root, "config")
		entries, err := os.ReadDir(configDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
					pc.ConfigFiles = append(pc.ConfigFiles, filepath.Join("config", entry.Name()))
				}
			}
		}
	} else if strings.HasPrefix(pc.FrameworkType, "codeigniter") {
		configDir := filepath.Join(root, "application", "config")
		entries, err := os.ReadDir(configDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
					pc.ConfigFiles = append(pc.ConfigFiles, filepath.Join("application", "config", entry.Name()))
				}
			}
		}
	}
}
func parseEnvFile(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		vars[key] = val
	}
	return vars
}
