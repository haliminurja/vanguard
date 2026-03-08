package resolver

import (
	"context"

	"vanguard/internal/models"
)

type ContextResolver interface {
	Name() string
	Resolve(ctx context.Context, root string, pc *models.ProjectContext) error
	Priority() int
}
