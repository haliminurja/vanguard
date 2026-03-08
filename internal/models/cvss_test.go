package models_test

import (
	"math"
	"testing"

	"vanguard/internal/models"
)

func TestCVSSv3Calculator(t *testing.T) {
	tests := []struct {
		vector   string
		expected float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", 1.9},
		{"", 0.0},
		{"INVALID:1.0/FOO:BAR", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got := models.CalculateCVSSv3BaseScore(tt.vector)
			if math.Abs(got-tt.expected) > 0.1 {
				t.Errorf("calculateCVSS(%q) = %v; want %v", tt.vector, got, tt.expected)
			}
		})
	}
}
