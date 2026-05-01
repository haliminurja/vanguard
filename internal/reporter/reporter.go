package reporter

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/haliminurja/vanguard/internal/models"
)

type Reporter interface {
	Name() string
	Format() string
	Generate(ctx context.Context, report *models.ScanReport) error
}

func ensureOutputDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating output directory %s: %w", dir, err)
	}
	return nil
}

func frameworkLabel(pc models.ProjectContext) string {
	framework := strings.TrimSpace(pc.FrameworkType)
	if framework == "" {
		return "Unknown"
	}

	names := map[string]string{
		"php-generic":  "PHP",
		"laravel":      "Laravel",
		"lumen":        "Lumen",
		"symfony":      "Symfony",
		"wordpress":    "WordPress",
		"codeigniter":  "CodeIgniter",
		"codeigniter2": "CodeIgniter 2",
		"codeigniter3": "CodeIgniter 3",
		"codeigniter4": "CodeIgniter 4",
		"yii2":         "Yii2",
		"cakephp":      "CakePHP",
		"nextjs":       "Next.js",
		"express":      "Express",
		"angular":      "Angular",
		"react":        "React",
		"vue":          "Vue",
		"laminas":      "Laminas",
		"phalcon":      "Phalcon",
		"drupal":       "Drupal",
		"joomla":       "Joomla",
		"magento":      "Magento",
	}
	label, ok := names[strings.ToLower(framework)]
	if !ok {
		label = framework
	}

	version := strings.TrimSpace(pc.FrameworkVersion)
	if version == "" && strings.EqualFold(framework, "laravel") {
		version = strings.TrimSpace(pc.LaravelVersion)
	}
	if version == "" {
		return label
	}
	return label + " " + version
}
