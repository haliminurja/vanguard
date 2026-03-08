package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type GitProvider struct {
	Depth   int
	tempDir string
}

func NewGitProvider(depth int) *GitProvider {
	if depth <= 0 {
		depth = 1
	}
	return &GitProvider{Depth: depth}
}

func (p *GitProvider) Acquire(ctx context.Context, repoURL string) (*SourceResult, error) {
	if !IsGitURL(repoURL) {
		return nil, fmt.Errorf("invalid repository URL scheme: %q", repoURL)
	}
	if strings.Contains(repoURL, "ext::") {
		return nil, fmt.Errorf("git ext:: protocol is not allowed: %q", repoURL)
	}
	if strings.HasPrefix(repoURL, "-") {
		return nil, fmt.Errorf("invalid repository URL starts with dash: %q", repoURL)
	}

	tmpDir, err := os.MkdirTemp("", "vanguard-scan-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}
	p.tempDir = tmpDir

	args := []string{"clone"}
	if p.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", p.Depth))
	}
	args = append(args, "--", repoURL, tmpDir)

	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("git clone failed: %w\n%s", err, string(output))
	}

	result := &SourceResult{
		RootPath:  tmpDir,
		IsLaravel: false,
		HasGit:    true,
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "artisan")); err == nil {
		result.IsLaravel = true
		return result, nil
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "composer.json"))
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

func (p *GitProvider) Cleanup() error {
	if p.tempDir != "" {
		return os.RemoveAll(p.tempDir)
	}
	return nil
}
func IsGitURL(path string) bool {
	return strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "git@") ||
		strings.HasPrefix(path, "ssh://") ||
		strings.HasSuffix(path, ".git")
}
