package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type LocalProvider struct{}

func NewLocalProvider() *LocalProvider {
	return &LocalProvider{}
}

func (p *LocalProvider) Acquire(_ context.Context, path string) (*SourceResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist: %s", absPath)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absPath)
	}

	result := &SourceResult{
		RootPath:  absPath,
		IsLaravel: false,
		HasGit:    false,
	}
	if _, err := os.Stat(filepath.Join(absPath, ".git")); err == nil {
		result.HasGit = true
	}
	if _, err := os.Stat(filepath.Join(absPath, "artisan")); err == nil {
		result.IsLaravel = true
		return result, nil
	}
	composerPath := filepath.Join(absPath, "composer.json")
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return result, nil
	}

	var composer struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return result, nil
	}

	if _, ok := composer.Require["laravel/framework"]; ok {
		result.IsLaravel = true
	}

	return result, nil
}

func (p *LocalProvider) Cleanup() error {
	return nil
}
