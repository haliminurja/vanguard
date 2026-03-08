package models

import "time"

type ScanReport struct {
	ProjectContext ProjectContext
	Findings       []Finding
	StartedAt      time.Time
	CompletedAt    time.Time
	Duration       time.Duration
	ScannersRun    []string
	ScannerErrors  map[string]string
}

func (r *ScanReport) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}
func (r *ScanReport) FindingsByCategory() map[string][]Finding {
	grouped := make(map[string][]Finding)
	for _, f := range r.Findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}
	return grouped
}
func (r *ScanReport) VanguardDefenseRating() int {
	if len(r.Findings) == 0 {
		return 100
	}

	penalty := 0
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			penalty += 15
		case SeverityHigh:
			penalty += 8
		case SeverityMedium:
			penalty += 3
		case SeverityLow:
			penalty += 1
		}
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score
}
func (r *ScanReport) DefenseGrade() string {
	score := r.VanguardDefenseRating()
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
func (r *ScanReport) CountByCWE() map[string]int {
	counts := make(map[string]int)
	for _, f := range r.Findings {
		if f.CWE != "" {
			counts[f.CWE]++
		}
	}
	return counts
}
func (r *ScanReport) CountByConfidence() map[string]int {
	counts := make(map[string]int)
	for _, f := range r.Findings {
		if f.Confidence != "" {
			counts[f.Confidence]++
		}
	}
	return counts
}
