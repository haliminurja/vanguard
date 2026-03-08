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

type fileContent struct {
	data  []byte
	lines []string
}

type RulesScanner struct {
	rules      []config.RuleDefinition
	fileCache  map[string]*fileContent
	cacheMu    sync.RWMutex
	targetList map[string][]string
	reCache    map[string]*regexp.Regexp
}

func NewRulesScanner(rules []config.RuleDefinition) *RulesScanner {
	scanner := &RulesScanner{
		rules:      rules,
		fileCache:  make(map[string]*fileContent),
		targetList: make(map[string][]string),
		reCache:    make(map[string]*regexp.Regexp),
	}
	scanner.precompile()
	return scanner
}

func (s *RulesScanner) precompile() {
	for _, rule := range s.rules {
		for _, pat := range rule.Patterns {
			if pat.Type == "regex" || pat.Type == "regex-multiline" {
				if _, ok := s.reCache[pat.Pattern]; !ok {
					if re, err := regexp.Compile(pat.Pattern); err == nil {
						s.reCache[pat.Pattern] = re
					}
				}
			}
			if pat.ExcludePattern != "" {
				if _, ok := s.reCache[pat.ExcludePattern]; !ok {
					if re, err := regexp.Compile(pat.ExcludePattern); err == nil {
						s.reCache[pat.ExcludePattern] = re
					}
				}
			}
		}
	}
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
				findings = append(findings, rf...)
				for _, f := range rf {
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
		return []models.Finding{s.buildFinding(rule, pat.Pattern, 0, "[POLA TIDAK DITEMUKAN]", nil, nil)}
	}

	if !found {
		return nil
	}

	var findings []models.Finding
	for _, m := range matches {
		rel, _ := filepath.Rel(root, m)
		findings = append(findings, s.buildFinding(rule, rel, 0, "[FILE EXISTS]", nil, nil))
	}
	return findings
}

func (s *RulesScanner) checkFileContent(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	files := s.getCachedTargetFiles(pat.Target, root)
	if len(files) == 0 {
		return nil
	}

	re := s.reCache[pat.Pattern]
	if (pat.Type == "regex" || pat.Type == "regex-multiline") && re == nil {
		return nil
	}

	var findings []models.Finding

	for _, fpath := range files {
		content, err := s.getFileContent(fpath)
		if err != nil {
			continue
		}

		var matches []match
		if pat.Type == "regex-multiline" {
			matches = s.scanContentMultiline(content, pat, re, fpath)
		} else {
			matches = s.scanContent(content, pat, re, fpath)
		}

		rel, _ := filepath.Rel(root, fpath)

		if pat.Negative {
			if len(matches) == 0 {
				findings = append(findings, s.buildFinding(rule, rel, 0, "[POLA TIDAK DITEMUKAN]", nil, nil))
			}
		} else {
			for _, m := range matches {
				findings = append(findings, s.buildFinding(rule, rel, m.line, m.text, m.contextBefore, m.contextAfter))
			}
		}
	}

	return findings
}

func (s *RulesScanner) getCachedTargetFiles(target, root string) []string {
	s.cacheMu.RLock()
	if list, ok := s.targetList[target]; ok {
		s.cacheMu.RUnlock()
		return list
	}
	s.cacheMu.RUnlock()

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	list := resolveTarget(target, root)
	s.targetList[target] = list
	return list
}

func (s *RulesScanner) getFileContent(path string) (*fileContent, error) {
	s.cacheMu.RLock()
	if fc, ok := s.fileCache[path]; ok {
		s.cacheMu.RUnlock()
		return fc, nil
	}
	s.cacheMu.RUnlock()

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	strData := string(data)
	lines := strings.Split(strData, "\n")
	fc := &fileContent{data: data, lines: lines}
	s.fileCache[path] = fc
	return fc, nil
}

type match struct {
	line          int
	text          string
	contextBefore []string
	contextAfter  []string
}

func (s *RulesScanner) scanContent(fc *fileContent, pat config.PatternDef, re *regexp.Regexp, path string) []match {
	excludeRe := s.reCache[pat.ExcludePattern]

	var matches []match

	if pat.Type == "regex" && re != nil {
		strData := string(fc.data)
		indexes := re.FindAllStringIndex(strData, -1)
		if len(indexes) == 0 {
			return nil
		}

		lineStarts := make([]int, len(fc.lines))
		pos := 0
		for i, l := range fc.lines {
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

			if excludeRe != nil {
				if excludeRe.MatchString(fc.lines[lineIdx]) || excludeRe.MatchString(filepath.ToSlash(path)) {
					continue
				}
			}

			m := match{
				line: lineIdx + 1,
				text: strings.TrimSpace(fc.lines[lineIdx]),
			}
			m.contextBefore = getContext(fc.lines, lineIdx, -3, -1)
			m.contextAfter = getContext(fc.lines, lineIdx, 1, 3)
			matches = append(matches, m)
		}
	} else {
		for i, line := range fc.lines {
			if pat.Type == "contains" && !strings.Contains(line, pat.Pattern) {
				continue
			}

			if excludeRe != nil {
				if excludeRe.MatchString(line) || excludeRe.MatchString(filepath.ToSlash(path)) {
					continue
				}
			}

			matches = append(matches, match{
				line:          i + 1,
				text:          strings.TrimSpace(line),
				contextBefore: getContext(fc.lines, i, -3, -1),
				contextAfter:  getContext(fc.lines, i, 1, 3),
			})
		}
	}

	return matches
}

func (s *RulesScanner) scanContentMultiline(fc *fileContent, pat config.PatternDef, re *regexp.Regexp, path string) []match {
	if re == nil {
		return nil
	}

	exRe := s.reCache[pat.ExcludePattern]
	if exRe != nil {
		if exRe.Match(fc.data) || exRe.MatchString(filepath.ToSlash(path)) {
			return nil
		}
	}

	indexes := re.FindAllStringIndex(string(fc.data), -1)
	if len(indexes) == 0 {
		return nil
	}

	var matches []match
	for _, loc := range indexes {
		start := loc[0]
		lineNum := 1 + strings.Count(string(fc.data[:start]), "\n")

		m := match{
			line: lineNum,
			text: "[MULTI-LINE MATCH]",
		}
		if lineNum-1 < len(fc.lines) {
			m.text = strings.TrimSpace(fc.lines[lineNum-1])
		}
		m.contextBefore = getContext(fc.lines, lineNum-1, -3, -1)
		m.contextAfter = getContext(fc.lines, lineNum-1, 1, 3)
		matches = append(matches, m)
	}

	return matches
}

func getContext(lines []string, center, startRel, endRel int) []string {
	var ctx []string
	start := center + startRel
	end := center + endRel
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for i := start; i <= end; i++ {
		if i == center {
			continue
		}
		ctx = append(ctx, lines[i])
	}
	return ctx
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
		exts := targetExts(target)
		var walkRoots []string

		switch target {
		case "php-files":
			walkRoots = []string{root}
		case "blade-files":
			walkRoots = []string{filepath.Join(root, "resources", "views")}
		case "twig-files":
			walkRoots = []string{filepath.Join(root, "templates")}
		case "js-files":
			walkRoots = []string{filepath.Join(root, "resources", "js")}
		case "config-files":
			walkRoots = []string{
				filepath.Join(root, "config"),
				filepath.Join(root, "application", "config"),
				filepath.Join(root, "app", "Config"),
			}
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

		for _, ext := range exts {
			if ext == "" {
				continue
			}
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
	case "twig-files":
		return []string{filepath.Join(root, "templates", "*.twig")}
	case "config-files":
		return []string{
			filepath.Join(root, "config", "*.php"),
			filepath.Join(root, "config", "*.yml"),
			filepath.Join(root, "config", "*.yaml"),
			filepath.Join(root, "application", "config", "*.php"),
			filepath.Join(root, "app", "Config", "*.php"),
		}
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
	case "php-files", "blade-files", "twig-files", "js-files", "config-files", "routes-files", "migration-files", "model-files", "service-files", "middleware-files", "controller-files", "request-files":
		return true
	default:
		return false
	}
}

func targetExts(target string) []string {
	switch target {
	case "php-files", "routes-files", "migration-files", "model-files", "service-files", "middleware-files", "controller-files", "request-files":
		return []string{".php"}
	case "blade-files":
		return []string{".blade.php"}
	case "js-files":
		return []string{".js"}
	case "twig-files":
		return []string{".twig"}
	case "config-files":
		return []string{".php", ".yaml", ".yml", ".xml"}
	default:
		return nil
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
	files := s.getCachedTargetFiles(pat.Target, root)
	if len(files) == 0 {
		return nil
	}

	threshold := 4.5
	if pat.Pattern != "" {
		fmt.Sscanf(pat.Pattern, "%f", &threshold)
	}

	var findings []models.Finding
	for _, fpath := range files {
		fc, err := s.getFileContent(fpath)
		if err != nil {
			continue
		}

		matches := scanContentEntropy(fc, threshold)
		rel, _ := filepath.Rel(root, fpath)
		for _, m := range matches {
			findings = append(findings, s.buildFinding(rule, rel, m.line, m.text, m.contextBefore, m.contextAfter))
		}
	}
	return findings
}

func scanContentEntropy(fc *fileContent, threshold float64) []match {
	var matches []match

	for i, line := range fc.lines {
		words := strings.FieldsFunc(line, func(r rune) bool {
			return r == '"' || r == '\'' || r == ' ' || r == '=' || r == ':'
		})
		for _, word := range words {
			if len(word) > 16 && calculateEntropy(word) > threshold {
				matches = append(matches, match{
					line:          i + 1,
					text:          strings.TrimSpace(line),
					contextBefore: getContext(fc.lines, i, -3, -1),
					contextAfter:  getContext(fc.lines, i, 1, 3),
				})
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
