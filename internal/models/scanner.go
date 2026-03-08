package models

import "context"

type Scanner interface {
	Name() string
	Description() string
	Scan(ctx context.Context, project ProjectContext, emit func(Finding)) ([]Finding, error)
}
type ScannerStatus int

const (
	ScannerPending ScannerStatus = iota
	ScannerRunning
	ScannerDone
	ScannerError
	ScannerSkipped
)

func (s ScannerStatus) String() string {
	switch s {
	case ScannerPending:
		return "Pending"
	case ScannerRunning:
		return "Running"
	case ScannerDone:
		return "Done"
	case ScannerError:
		return "Error"
	case ScannerSkipped:
		return "Skipped"
	default:
		return "Unknown"
	}
}

type ScannerInfo struct {
	Name         string
	Description  string
	Status       ScannerStatus
	FindingCount int
	Error        error
}
