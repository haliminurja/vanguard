package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"vanguard/internal/models"
)

const (
	osvQueryURL = "https://api.osv.dev/v1/query"
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	batchSize   = 100
	httpTimeout = 30 * time.Second
)

type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{
		client: &http.Client{Timeout: httpTimeout},
	}
}

func (s *Scanner) Name() string        { return "dependency-scanner" }
func (s *Scanner) Description() string { return "Live CVE checks via OSV.dev (Packagist SBOM)" }

func (s *Scanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	if len(project.InstalledPackages) == 0 {
		return nil, nil
	}
	vulnPackages, err := s.batchQuery(ctx, project.InstalledPackages)
	if err != nil {
		return nil, fmt.Errorf("querying OSV.dev: %w", err)
	}

	if len(vulnPackages) == 0 {
		return nil, nil
	}
	var findings []models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, vp := range vulnPackages {
		wg.Add(1)
		go func(vp vulnPackage) {
			defer wg.Done()
			vulns, err := s.queryPackage(ctx, vp.name, vp.version, vp.ecosystem)
			if err != nil {
				return
			}

			for _, vuln := range vulns {
				f := vulnToFinding(s.Name(), vp.name, vp.version, vp.ecosystem, vp.file, vuln)
				mu.Lock()
				findings = append(findings, f)
				emit(f)
				mu.Unlock()
			}
		}(vp)
	}

	wg.Wait()

	return findings, nil
}
func (s *Scanner) doRequestWithRetries(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i <= maxRetries; i++ {
		resp, err = s.client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if i == maxRetries {
			break
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		time.Sleep(backoff)
		backoff *= 2
	}

	return resp, err
}

type vulnPackage struct {
	name      string
	version   string
	ecosystem string
	file      string
}

func (s *Scanner) batchQuery(ctx context.Context, packages []models.Package) ([]vulnPackage, error) {
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}

	var allQueries []query
	var packageOrder []vulnPackage

	for _, p := range packages {
		version := normalizeVersion(p.Version)
		if version == "" {
			continue
		}
		q := query{Version: version}
		q.Package.Name = p.Name
		q.Package.Ecosystem = p.Ecosystem
		allQueries = append(allQueries, q)
		packageOrder = append(packageOrder, vulnPackage{name: p.Name, version: version, ecosystem: p.Ecosystem, file: p.File})
	}
	var affected []vulnPackage
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < len(allQueries); i += batchSize {
		end := i + batchSize
		if end > len(allQueries) {
			end = len(allQueries)
		}

		batch := allQueries[i:end]
		batchOrder := packageOrder[i:end]

		wg.Add(1)
		go func(batch []query, batchOrder []vulnPackage) {
			defer wg.Done()

			body, err := json.Marshal(map[string]any{"queries": batch})
			if err != nil {
				return
			}
			req, err := http.NewRequestWithContext(ctx, "POST", osvBatchURL, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := s.doRequestWithRetries(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				return
			}

			var result struct {
				Results []struct {
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulns"`
				} `json:"results"`
			}

			data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()

			if err != nil {
				return
			}

			if err := json.Unmarshal(data, &result); err != nil {
				return
			}

			var batchAffected []vulnPackage
			for j, r := range result.Results {
				if len(r.Vulns) > 0 && j < len(batchOrder) {
					batchAffected = append(batchAffected, batchOrder[j])
				}
			}

			mu.Lock()
			affected = append(affected, batchAffected...)
			mu.Unlock()
		}(batch, batchOrder)
	}

	wg.Wait()

	return affected, nil
}
func (s *Scanner) queryPackage(ctx context.Context, name, version, ecosystem string) ([]osvVuln, error) {
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{
			"name":      name,
			"ecosystem": ecosystem,
		},
		"version": version,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.doRequestWithRetries(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV.dev returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulns []osvVuln `json:"vulns"`
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading OSV.dev response: %w", err)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Vulns, nil
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	References       []osvReference `json:"references"`
	Affected         []osvAffected  `json:"affected"`
	DatabaseSpecific osvDBSpecific  `json:"database_specific"`
	Severity         []osvSeverity  `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvDBSpecific struct {
	Severity string   `json:"severity"`
	CWEIDs   []string `json:"cwe_ids"`
}

func vulnToFinding(scanner, pkgName, pkgVersion, ecosystem, file string, vuln osvVuln) models.Finding {
	cveID := vuln.ID
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}
	severity := parseSeverity(vuln.DatabaseSpecific.Severity)
	fixedVersion := extractFixedVersion(vuln.Affected, pkgName)
	var refs []string
	for _, ref := range vuln.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			refs = append(refs, ref.URL)
		}
	}
	if len(refs) > 3 {
		refs = refs[:3]
	}
	description := vuln.Summary
	if description == "" && len(vuln.Details) > 0 {
		description = vuln.Details
		if len(description) > 300 {
			description = description[:300] + "..."
		}
	}
	remediation := fmt.Sprintf("Run: composer update %s", pkgName)
	if ecosystem == "npm" {
		remediation = fmt.Sprintf("Run: npm update %s", pkgName)
	}

	if fixedVersion != "" {
		if ecosystem == "npm" {
			remediation = fmt.Sprintf("Upgrade %s to %s or later:\n  npm install %s@^%s", pkgName, fixedVersion, pkgName, fixedVersion)
		} else {
			remediation = fmt.Sprintf("Upgrade %s to %s or later:\n  composer require %s:%s", pkgName, fixedVersion, pkgName, fixedVersion)
		}
	}

	var tags []string
	var primaryCWE string

	if len(vuln.DatabaseSpecific.CWEIDs) > 0 {
		primaryCWE = vuln.DatabaseSpecific.CWEIDs[0]
		for _, cwe := range vuln.DatabaseSpecific.CWEIDs {
			tags = append(tags, strings.ToLower(cwe))
		}
	}
	var cvssScore float64
	var cvssVector string
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			cvssVector = sev.Score
			cvssScore = models.CalculateCVSSv3BaseScore(cvssVector)
			break
		}
	}

	return models.Finding{
		ID:          cveID,
		Title:       fmt.Sprintf("[%s] %s@%s — %s", cveID, pkgName, pkgVersion, vuln.Summary),
		Description: description,
		Severity:    severity,
		Category:    "Dependencies",
		Scanner:     scanner,
		File:        file,
		Remediation: remediation,
		References:  refs,
		Tags:        tags,
		CWE:         primaryCWE,
		CVSSScore:   cvssScore,
		CVSSVector:  cvssVector,
	}
}

func extractFixedVersion(affected []osvAffected, pkgName string) string {
	for _, a := range affected {
		if a.Package.Name != pkgName {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func parseSeverity(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MODERATE", "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if strings.HasPrefix(v, "dev-") || v == "" {
		return ""
	}
	return v
}
