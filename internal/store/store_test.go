package store

import (
	"testing"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Normal Project", "Normal_Project"},
		{"../../etc/passwd", "______etc_passwd"},
		{"..\\..\\windows\\system32", "______windows_system32"},
		{"foo/bar<>|&*^%$baz", "foo_barbaz"},
		{"", "unnamed_project"},
	}

	for _, test := range tests {
		actual := sanitizeName(test.input)
		if actual != test.expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", test.input, actual, test.expected)
		}
	}
}
