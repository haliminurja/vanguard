package scanner

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sync"

	"vanguard/internal/config"
	"vanguard/internal/models"
)

type RulesScanner struct {
	rules []config.RuleDefinition
}

func NewRulesScanner(rules []config.RuleDefinition) *RulesScanner {
	return &RulesScanner{rules: rules}
}

func (s *RulesScanner) Name() string        { return "rules-scanner" }
func (s *RulesScanner) Description() string { return "Custom YAML rule checks" }

func (s *RulesScanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	var findings []models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	errCh := make(chan error, 1)

	for _, rule := range s.rules {

		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}

		wg.Add(1)
		go func(r config.RuleDefinition) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				select {
				case errCh <- ctx.Err():
				default:
				}
				return
			default:
			}

			rf := s.evaluateRule(r, project.RootPath)
			if len(rf) > 0 {
				mu.Lock()
				for _, f := range rf {
					findings = append(findings, f)
					emit(f)
				}
				mu.Unlock()
			}
		}(rule)
	}

	wg.Wait()

	select {
	case err := <-errCh:
		return findings, err
	default:
	}

	return findings, nil
}

func (s *RulesScanner) evaluateRule(rule config.RuleDefinition, root string) []models.Finding {
	var findings []models.Finding

	condition := rule.Condition
	if condition == "" {
		condition = "any"
	}

	if condition == "all" {
		if len(rule.Patterns) == 0 {
			return findings
		}

		fileMatches := make(map[string]map[int][]models.Finding)

		for i, pat := range rule.Patterns {
			pf := s.evaluatePattern(rule, pat, root)
			for _, f := range pf {
				if fileMatches[f.File] == nil {
					fileMatches[f.File] = make(map[int][]models.Finding)
				}
				fileMatches[f.File][i] = append(fileMatches[f.File][i], f)
			}
		}

		for _, patMap := range fileMatches {
			if len(patMap) == len(rule.Patterns) {

				for i := 0; i < len(rule.Patterns); i++ {
					if fs, ok := patMap[i]; ok && len(fs) > 0 {
						findings = append(findings, fs...)
						break
					}
				}
			}
		}
	} else {

		for _, pat := range rule.Patterns {
			pf := s.evaluatePattern(rule, pat, root)
			findings = append(findings, pf...)
		}
	}

	return findings
}

func allPatternsMatched(results [][]models.Finding) bool {
	for _, r := range results {
		if len(r) == 0 {
			return false
		}
	}
	return true
}

func (s *RulesScanner) evaluatePattern(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	switch pat.Type {
	case "file-exists":
		return s.checkFileExists(rule, pat, root)
	case "regex", "contains", "regex-multiline":
		return s.checkFileContent(rule, pat, root)
	case "entropy":
		return s.checkEntropy(rule, pat, root)
	default:
		return nil
	}
}

func (s *RulesScanner) checkFileExists(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	matches, _ := filepath.Glob(filepath.Join(root, pat.Pattern))
	found := len(matches) > 0

	if pat.Negative {
		if found {
			return nil
		}
		return []models.Finding{s.buildFinding(rule, pat.Pattern, 0, "", nil, nil)}
	}

	if !found {
		return nil
	}

	var findings []models.Finding
	for _, m := range matches {
		rel, _ := filepath.Rel(root, m)
		findings = append(findings, s.buildFinding(rule, rel, 0, "", nil, nil))
	}
	return findings
}

func (s *RulesScanner) checkFileContent(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	files := resolveTarget(pat.Target, root)
	if len(files) == 0 {
		return nil
	}

	var re *regexp.Regexp
	if pat.Type == "regex" || pat.Type == "regex-multiline" {
		var err error
		re, err = regexp.Compile(pat.Pattern)
		if err != nil {
			return nil
		}
	}

	var findings []models.Finding

	for _, fpath := range files {
		var matches []match
		if pat.Type == "regex-multiline" {

			matches = scanFileMultiline(fpath, pat, re)
		} else {
			matches = scanFile(fpath, pat, re)
		}

		rel, _ := filepath.Rel(root, fpath)

		if pat.Negative {

			if len(matches) == 0 {
				findings = append(findings, s.buildFinding(rule, rel, 0, "", nil, nil))
			}
		} else {
			for _, m := range matches {
				findings = append(findings, s.buildFinding(rule, rel, m.line, m.text, m.contextBefore, m.contextAfter))
			}
		}
	}

	return findings
}

type match struct {
	line          int
	text          string
	contextBefore []string
	contextAfter  []string
}

func scanFile(path string, pat config.PatternDef, re *regexp.Regexp) []match {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	strData := string(data)
	lines := strings.Split(strData, "\n")

	var excludeRe *regexp.Regexp
	if pat.ExcludePattern != "" {
		excludeRe, _ = regexp.Compile(pat.ExcludePattern)
	}

	var matches []match

	if pat.Type == "regex" && re != nil {
		indexes := re.FindAllStringIndex(strData, -1)
		if len(indexes) == 0 {
			return nil
		}

		lineStarts := make([]int, len(lines))
		pos := 0
		for i, l := range lines {
			lineStarts[i] = pos
			pos += len(l) + 1
		}

		seenLines := make(map[int]bool)

		for _, loc := range indexes {
			startIdx := loc[0]
			lineIdx := 0
			for i := 1; i < len(lineStarts); i++ {
				if lineStarts[i] > startIdx {
					break
				}
				lineIdx = i
			}

			if seenLines[lineIdx] {
				continue
			}
			seenLines[lineIdx] = true

			matched := true
			if excludeRe != nil {
				if excludeRe.MatchString(lines[lineIdx]) || excludeRe.MatchString(filepath.ToSlash(path)) {
					matched = false
				}
			}

			if matched {
				m := match{
					line: lineIdx + 1,
					text: strings.TrimSpace(lines[lineIdx]),
				}
				start := lineIdx - 2
				if start < 0 {
					start = 0
				}
				for j := start; j < lineIdx; j++ {
					m.contextBefore = append(m.contextBefore, lines[j])
				}
				end := lineIdx + 3
				if end > len(lines) {
					end = len(lines)
				}
				for j := lineIdx + 1; j < end; j++ {
					m.contextAfter = append(m.contextAfter, lines[j])
				}
				matches = append(matches, m)
			}
		}
	} else {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)

			matched := false
			if pat.Type == "contains" {
				matched = strings.Contains(line, pat.Pattern)
			}

			if matched && excludeRe != nil {
				if excludeRe.MatchString(line) || excludeRe.MatchString(filepath.ToSlash(path)) {
					matched = false
				}
			}

			if matched {
				m := match{
					line: i + 1,
					text: trimmed,
				}
				start := i - 2
				if start < 0 {
					start = 0
				}
				for j := start; j < i; j++ {
					m.contextBefore = append(m.contextBefore, lines[j])
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				for j := i + 1; j < end; j++ {
					m.contextAfter = append(m.contextAfter, lines[j])
				}
				matches = append(matches, m)
			}
		}
	}

	return matches
}

func scanFileMultiline(path string, pat config.PatternDef, re *regexp.Regexp) []match {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	if pat.ExcludePattern != "" {
		exRe, _ := regexp.Compile(pat.ExcludePattern)
		if exRe.Match(data) || exRe.MatchString(filepath.ToSlash(path)) {
			return nil
		}
	}

	if re == nil {
		return nil
	}

	if re.Match(data) {

		return []match{{line: 1, text: ""}}
	}
	return nil
}

func resolveTarget(target, root string) []string {
	patterns := targetGlobs(target, root)

	var files []string
	seen := make(map[string]bool)

	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if seen[m] {
				continue
			}
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			seen[m] = true
			files = append(files, m)
		}
	}

	if needsWalk(target) {
		ext := targetExt(target)
		var walkRoots []string

		switch target {
		case "php-files":
			walkRoots = []string{root}
		case "blade-files":
			walkRoots = []string{filepath.Join(root, "resources", "views")}
		case "js-files":
			walkRoots = []string{filepath.Join(root, "resources", "js")}
		case "config-files":
			walkRoots = []string{filepath.Join(root, "config")}
		case "routes-files":
			walkRoots = []string{filepath.Join(root, "routes")}
		case "migration-files":
			walkRoots = []string{filepath.Join(root, "database", "migrations")}
		case "middleware-files":
			walkRoots = []string{filepath.Join(root, "app", "Http", "Middleware")}
		case "model-files":
			walkRoots = []string{filepath.Join(root, "app", "Models"), filepath.Join(root, "app")}
		case "service-files":
			walkRoots = []string{filepath.Join(root, "app", "Services")}
		case "controller-files":
			walkRoots = []string{filepath.Join(root, "app", "Http", "Controllers")}
		case "request-files":
			walkRoots = []string{filepath.Join(root, "app", "Http", "Requests")}
		default:
			walkRoots = []string{root}
		}

		if ext != "" {
			for _, wRoot := range walkRoots {
				_ = filepath.Walk(wRoot, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}
					if info.IsDir() {
						if skipDir(info.Name()) {
							return filepath.SkipDir
						}

						return nil
					}
					if matchesExt(path, ext) && !seen[path] {
						seen[path] = true
						files = append(files, path)
					}
					return nil
				})
			}
		}
	}

	return files
}

func targetGlobs(target, root string) []string {
	switch target {
	case "php-files":
		return []string{filepath.Join(root, "*.php"), filepath.Join(root, "app", "*.php")}
	case "blade-files":
		return []string{filepath.Join(root, "resources", "views", "*.blade.php")}
	case "config-files":
		return []string{filepath.Join(root, "config", "*.php")}
	case "env-files":
		return []string{filepath.Join(root, ".env"), filepath.Join(root, ".env.*")}
	case "routes-files":
		return []string{filepath.Join(root, "routes", "*.php")}
	case "migration-files":
		return []string{filepath.Join(root, "database", "migrations", "*.php")}
	case "js-files":
		return []string{filepath.Join(root, "resources", "js", "*.js"), filepath.Join(root, "resources", "js", "*.ts")}
	case "composer-files":
		return []string{filepath.Join(root, "composer.json"), filepath.Join(root, "composer.lock")}
	case "middleware-files":
		return []string{filepath.Join(root, "app", "Http", "Middleware", "*.php")}
	case "model-files":
		return []string{filepath.Join(root, "app", "Models", "*.php"), filepath.Join(root, "app", "*.php")}
	case "service-files":
		return []string{filepath.Join(root, "app", "Services", "*.php")}
	case "controller-files":
		return []string{filepath.Join(root, "app", "Http", "Controllers", "*.php")}
	case "request-files":
		return []string{filepath.Join(root, "app", "Http", "Requests", "*.php")}
	default:

		if strings.ContainsAny(target, "*?[") {
			return []string{filepath.Join(root, target)}
		}
		return nil
	}
}

func needsWalk(target string) bool {
	switch target {
	case "php-files", "blade-files", "js-files", "config-files", "routes-files", "migration-files", "model-files", "service-files", "middleware-files", "controller-files", "request-files":
		return true
	default:
		return false
	}
}

func targetExt(target string) string {
	switch target {
	case "php-files", "config-files", "routes-files", "migration-files", "model-files", "service-files", "middleware-files", "controller-files", "request-files":
		return ".php"
	case "blade-files":
		return ".blade.php"
	case "js-files":
		return ".js"
	default:
		return ""
	}
}

func matchesExt(path, ext string) bool {
	if ext == ".php" {
		return strings.HasSuffix(path, ".php")
	}
	if ext == ".blade.php" {
		return strings.HasSuffix(path, ".blade.php")
	}
	if ext == ".js" {
		return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".ts") ||
			strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".tsx")
	}
	return strings.HasSuffix(path, ext)
}

var extraSkipDirs []string

func SetExtraSkipDirs(dirs []string) {
	extraSkipDirs = dirs
}

func skipDir(name string) bool {
	switch name {
	case "vendor", "node_modules", ".git", "storage", ".idea", ".vscode":
		return true
	}
	for _, d := range extraSkipDirs {
		if name == d {
			return true
		}
	}
	return false
}

func (s *RulesScanner) checkEntropy(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	files := resolveTarget(pat.Target, root)
	if len(files) == 0 {
		return nil
	}

	threshold := 4.5
	if pat.Pattern != "" {

		fmt.Sscanf(pat.Pattern, "%f", &threshold)
	}

	var findings []models.Finding
	for _, fpath := range files {
		matches := scanFileEntropy(fpath, threshold)
		rel, _ := filepath.Rel(root, fpath)
		for _, m := range matches {
			findings = append(findings, s.buildFinding(rule, rel, m.line, m.text, m.contextBefore, m.contextAfter))
		}
	}
	return findings
}

func scanFileEntropy(path string, threshold float64) []match {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var matches []match

	for i, line := range lines {
		words := strings.FieldsFunc(line, func(r rune) bool {
			return r == '"' || r == '\'' || r == ' ' || r == '=' || r == ':'
		})
		for _, word := range words {
			if len(word) > 16 && calculateEntropy(word) > threshold {
				m := match{
					line: i + 1,
					text: strings.TrimSpace(line),
				}

				start := i - 2
				if start < 0 {
					start = 0
				}
				for j := start; j < i; j++ {
					m.contextBefore = append(m.contextBefore, lines[j])
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				for j := i + 1; j < end; j++ {
					m.contextAfter = append(m.contextAfter, lines[j])
				}
				matches = append(matches, m)
				break
			}
		}
	}
	return matches
}

func calculateEntropy(s string) float64 {
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	for _, count := range counts {
		freq := float64(count) / float64(len(s))
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

func (s *RulesScanner) buildFinding(rule config.RuleDefinition, file string, line int, snippet string, before, after []string) models.Finding {
	return models.Finding{
		ID:            rule.ID,
		Title:         rule.Title,
		Description:   rule.Description,
		Severity:      parseRuleSeverity(rule.Severity),
		Category:      rule.Category,
		Scanner:       s.Name(),
		File:          file,
		Line:          line,
		CodeSnippet:   truncate(snippet, 200),
		ContextBefore: before,
		ContextAfter:  after,
		Remediation:   rule.Remediation,
		References:    rule.References,
		Tags:          rule.Tags,
		Confidence:    rule.Confidence,
	}
}

func parseRuleSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... (%d chars)", len(s))
}
