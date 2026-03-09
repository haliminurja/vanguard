package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
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
	maxRetries  = 3
)

type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 20,
			},
		},
	}
}

func (s *Scanner) Name() string        { return "dependency-scanner" }
func (s *Scanner) Description() string { return "Enterprise-grade live CVE checks via OSV.dev" }

func (s *Scanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	if len(project.InstalledPackages) == 0 {
		return nil, nil
	}

	vulnPackages, err := s.batchQuery(ctx, project.InstalledPackages)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities: %w", err)
	}

	if len(vulnPackages) == 0 {
		return nil, nil
	}

	groupedPackages := make(map[packageLookupKey][]vulnPackage)
	var uniquePackages []packageLookupKey
	for _, vp := range vulnPackages {
		key := packageLookupKey{
			name:      vp.name,
			version:   vp.version,
			ecosystem: vp.ecosystem,
		}
		if _, exists := groupedPackages[key]; !exists {
			uniquePackages = append(uniquePackages, key)
		}
		groupedPackages[key] = append(groupedPackages[key], vp)
	}

	var findings []models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	numWorkers := runtime.NumCPU()
	if numWorkers > 10 {
		numWorkers = 10
	}

	packageChan := make(chan packageLookupKey, len(uniquePackages))
	for _, pkg := range uniquePackages {
		packageChan <- pkg
	}
	close(packageChan)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range packageChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				vulns, err := s.queryPackage(ctx, pkg.name, pkg.version, pkg.ecosystem)
				if err != nil {
					continue
				}

				seenVulns := make(map[string]bool)
				for _, vuln := range vulns {
					vulnKey := strings.TrimSpace(vuln.ID)
					if vulnKey == "" {
						vulnKey = strings.TrimSpace(vuln.Summary)
					}
					if seenVulns[vulnKey] {
						continue
					}
					seenVulns[vulnKey] = true

					for _, ref := range groupedPackages[pkg] {
						f := vulnToFinding(s.Name(), ref.name, ref.version, ref.ecosystem, ref.file, vuln)
						mu.Lock()
						findings = append(findings, f)
						emit(f)
						mu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()
	return findings, nil
}

func (s *Scanner) doRequestWithRetries(req *http.Request) (*http.Response, error) {
	var lastErr error
	backoff := 1 * time.Second

	for i := 0; i <= maxRetries; i++ {
		if i > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("resetting request body: %w", err)
			}
			req.Body = body
		}

		resp, err := s.client.Do(req)
		if err == nil {
			// Successful response or terminal error (e.g., 400 Bad Request)
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				return resp, nil
			}
			// Server error or rate limit, retry
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}

		if i < maxRetries {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}

	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

type vulnPackage struct {
	name      string
	version   string
	ecosystem string
	file      string
}

type packageLookupKey struct {
	name      string
	version   string
	ecosystem string
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
	var queryOrder []packageLookupKey
	queryRefs := make(map[packageLookupKey][]vulnPackage)
	seenQueries := make(map[packageLookupKey]bool)

	for _, p := range packages {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Ecosystem) == "" {
			continue
		}

		version := normalizeVersion(p.Version)
		if version == "" {
			continue
		}

		key := packageLookupKey{
			name:      p.Name,
			version:   version,
			ecosystem: p.Ecosystem,
		}
		queryRefs[key] = append(queryRefs[key], vulnPackage{name: p.Name, version: version, ecosystem: p.Ecosystem, file: p.File})
		if seenQueries[key] {
			continue
		}
		seenQueries[key] = true

		q := query{Version: version}
		q.Package.Name = p.Name
		q.Package.Ecosystem = p.Ecosystem
		allQueries = append(allQueries, q)
		queryOrder = append(queryOrder, key)
	}

	if len(allQueries) == 0 {
		return nil, nil
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
		batchOrder := queryOrder[i:end]

		wg.Add(1)
		go func(b []query, bo []packageLookupKey) {
			defer wg.Done()

			body, _ := json.Marshal(map[string]any{"queries": b})
			req, err := http.NewRequestWithContext(ctx, "POST", osvBatchURL, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := s.doRequestWithRetries(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			var result struct {
				Results []struct {
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulns"`
				} `json:"results"`
			}

			if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&result); err != nil {
				return
			}

			var batchAffected []vulnPackage
			for j, r := range result.Results {
				if len(r.Vulns) > 0 && j < len(bo) {
					batchAffected = append(batchAffected, queryRefs[bo[j]]...)
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
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{
			"name":      name,
			"ecosystem": ecosystem,
		},
		"version": version,
	})

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

	var result struct {
		Vulns []osvVuln `json:"vulns"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
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

	var cvssScore float64
	var cvssVector string
	for _, sev := range vuln.Severity {
		sevType := strings.ToUpper(strings.TrimSpace(sev.Type))
		if sevType == "CVSS_V3" || sevType == "CVSS_V31" || sevType == "CVSS_V30" {
			cvssVector = sev.Score
			cvssScore = models.CalculateCVSSv3BaseScore(cvssVector)
			break
		}
	}

	severity := deriveSeverity(vuln.DatabaseSpecific.Severity, cvssScore)
	fixedVersion := extractFixedVersion(vuln.Affected, pkgName)

	var refs []string
	seenRefs := make(map[string]bool)
	for _, ref := range vuln.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			if seenRefs[ref.URL] {
				continue
			}
			seenRefs[ref.URL] = true
			refs = append(refs, ref.URL)
		}
	}
	if len(refs) > 3 {
		refs = refs[:3]
	}

	summary := strings.TrimSpace(vuln.Summary)
	description := summary
	if description == "" {
		description = strings.TrimSpace(vuln.Details)
		if len(description) > 300 {
			description = description[:300] + "..."
		}
	}
	if description == "" {
		description = "Known security vulnerability"
	}
	if summary == "" {
		summary = description
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

	return models.Finding{
		ID:          cveID,
		Title:       fmt.Sprintf("[%s] %s@%s - %s", cveID, pkgName, pkgVersion, summary),
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

func deriveSeverity(osvSeverity string, cvssScore float64) models.Severity {
	if strings.TrimSpace(osvSeverity) != "" {
		return parseSeverity(osvSeverity)
	}

	switch {
	case cvssScore >= 9.0:
		return models.SeverityCritical
	case cvssScore >= 7.0:
		return models.SeverityHigh
	case cvssScore >= 4.0:
		return models.SeverityMedium
	case cvssScore > 0:
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if idx := strings.IndexAny(v, " \t"); idx > 0 {
		v = v[:idx]
	}
	if strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev") || strings.Contains(v, "x-dev") {
		return ""
	}
	if strings.ContainsAny(v, "^~*<>|,") || v == "" {
		return ""
	}
	return v
}
