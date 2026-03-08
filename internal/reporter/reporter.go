package reporter

import (
	"context"

	"vanguard/internal/models"
)

type Reporter interface {
	Name() string
	Format() string
	Generate(ctx context.Context, report *models.ScanReport) error
}
