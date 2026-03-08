package provider

import "context"

type SourceProvider interface {
	Acquire(ctx context.Context, path string) (*SourceResult, error)
	Cleanup() error
}
type SourceResult struct {
	RootPath  string
	IsLaravel bool
	HasGit    bool
}
