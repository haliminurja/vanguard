package orchestrator

import (
	"bufio"
	"github.com/haliminurja/vanguard/internal/config"
	"github.com/haliminurja/vanguard/internal/models"
	"os"
	"path/filepath"
	"strings"
)

type IgnoreProcessor struct {
	root   string
	config *config.IgnoreConfig
}

func NewIgnoreProcessor(root string, cfg *config.IgnoreConfig) *IgnoreProcessor {
	return &IgnoreProcessor{root: root, config: cfg}
}

func (ip *IgnoreProcessor) ShouldIgnore(f models.Finding) bool {

	for _, rid := range ip.config.Rules {
		if rid == f.ID {
			return true
		}
	}

	for _, pattern := range ip.config.Paths {
		match, err := filepath.Match(pattern, f.File)
		if err == nil && match {
			return true
		}

		if strings.HasPrefix(f.File, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}

	if f.File != "" && f.Line > 0 {
		if ip.hasIgnoreComment(f) {
			return true
		}
	}

	return false
}

func (ip *IgnoreProcessor) hasIgnoreComment(f models.Finding) bool {
	absPath := f.File
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(ip.root, f.File)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentLine := 0
	for scanner.Scan() {
		currentLine++
		if currentLine == f.Line {
			lineText := scanner.Text()

			if strings.Contains(lineText, "@vanguard-ignore") {
				return true
			}

			return false
		}
	}
	return false
}
