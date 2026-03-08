package models

import (
	"crypto/sha256"
	"fmt"
)

type Finding struct {
	ID            string
	Title         string
	Description   string
	Severity      Severity
	Category      string
	Scanner       string
	File          string
	Line          int
	CodeSnippet   string
	ContextBefore []string
	ContextAfter  []string
	Remediation   string
	References    []string
	Tags          []string
	CWE           string
	Confidence    string
	CVSSScore     float64
	CVSSVector    string
}

func (f Finding) Fingerprint() string {
	content := f.CodeSnippet
	if content == "" {
		content = f.Title
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", f.ID, f.File, content)))
	return fmt.Sprintf("%x", h[:12])
}
