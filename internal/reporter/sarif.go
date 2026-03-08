package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vanguard/internal/models"
)

type SARIFReporter struct {
	OutputDir string
	Version   string
}

func NewSARIFReporter(outputDir string, version string) *SARIFReporter {
	if outputDir == "" {
		outputDir = "."
	}
	if version == "" {
		version = "dev"
	}
	return &SARIFReporter{OutputDir: outputDir, Version: version}
}

func (r *SARIFReporter) Name() string   { return "sarif" }
func (r *SARIFReporter) Format() string { return "sarif" }

func (r *SARIFReporter) Generate(_ context.Context, report *models.ScanReport) error {
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range report.Findings {
		if _, exists := ruleIndex[f.ID]; !exists {
			ruleIndex[f.ID] = len(rules)
			rule := sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				DefaultConfiguration: sarifRuleConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
				Help: sarifMessage{Text: f.Remediation},
				Properties: sarifRuleProperties{
					Tags:       buildSARIFTags(f),
					Security:   severityToSARIFSecurity(f.Severity),
					Confidence: f.Confidence,
					CWE:        f.CWE,
				},
			}
			rules = append(rules, rule)
		}
	}
	var results []sarifResult
	for _, f := range report.Findings {
		msgText := f.Title
		if f.Description != "" {
			msgText = f.Title + " — " + f.Description
		}
		result := sarifResult{
			RuleID:    f.ID,
			RuleIndex: ruleIndex[f.ID],
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msgText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine: max(f.Line, 1),
						},
					},
				},
			},
		}
		if f.CodeSnippet != "" {
			region := &sarifRegion{
				StartLine: max(f.Line, 1),
				Snippet:   &sarifSnippet{Text: f.CodeSnippet},
			}

			if len(f.ContextBefore) > 0 || len(f.ContextAfter) > 0 {
				var contextText strings.Builder
				for _, l := range f.ContextBefore {
					contextText.WriteString(l + "\n")
				}
				contextText.WriteString(f.CodeSnippet + "\n")
				for _, l := range f.ContextAfter {
					contextText.WriteString(l + "\n")
				}

				region.ContextRegion = &sarifContextRegion{
					Snippet: &sarifSnippet{Text: contextText.String()},
				}
				if len(f.ContextBefore) > 0 {
					region.ContextRegion.StartLine = max(f.Line-len(f.ContextBefore), 1)
				} else {
					region.ContextRegion.StartLine = max(f.Line, 1)
				}
			}
			result.Locations[0].PhysicalLocation.Region = *region
		}
		result.PartialFingerprints = map[string]string{"primaryLocationLineHash/v1": f.Fingerprint()}
		results = append(results, result)
	}

	sarifDoc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "vanguard",
						InformationURI:  "https://github.com/your-repo/vanguard",
						Version:         r.Version,
						SemanticVersion: r.Version,
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling SARIF report: %w", err)
	}

	outPath := filepath.Join(r.OutputDir, "vanguard-report.sarif")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("writing SARIF report to %s: %w", outPath, err)
	}

	return nil
}

func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func severityToSARIFSecurity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "informational"
	}
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfig     `json:"defaultConfiguration"`
	Help                 sarifMessage        `json:"help"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags       []string `json:"tags"`
	Security   string   `json:"security-severity"`
	Confidence string   `json:"confidence,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine     int                 `json:"startLine"`
	Snippet       *sarifSnippet       `json:"snippet,omitempty"`
	ContextRegion *sarifContextRegion `json:"contextRegion,omitempty"`
}

type sarifContextRegion struct {
	StartLine int           `json:"startLine"`
	Snippet   *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

func buildSARIFTags(f models.Finding) []string {
	seen := make(map[string]bool)
	var tags []string
	if f.Category != "" {
		seen[f.Category] = true
		tags = append(tags, f.Category)
	}
	if f.CWE != "" && !seen[f.CWE] {
		seen[f.CWE] = true
		tags = append(tags, "external/cwe/"+strings.ToLower(f.CWE))
	}
	for _, t := range f.Tags {
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}

	return tags
}
