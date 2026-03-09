package scanner

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"vanguard/internal/config"
	"vanguard/internal/models"
)

const (
	MaxFileSize  = 5 * 1024 * 1024
	RegexTimeout = 2 * time.Second
)

type fileContent struct {
	data  []byte
	text  string
	lines []string
}

type ruleEvidence struct {
	file    string
	line    int
	snippet string
	lines   []string
	lineIdx int
}

type RulesScanner struct {
	rules       []config.RuleDefinition
	targetFiles map[string][]string
	reCache     map[string]*regexp.Regexp
	cacheMu     sync.RWMutex
}

func NewRulesScanner(rules []config.RuleDefinition) *RulesScanner {
	scanner := &RulesScanner{
		rules:       rules,
		targetFiles: make(map[string][]string),
		reCache:     make(map[string]*regexp.Regexp),
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
func (s *RulesScanner) Description() string { return "Elite high-performance security engine" }

func (s *RulesScanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	targetToRules := make(map[string][]config.RuleDefinition)
	var projectScopedRules []config.RuleDefinition
	var findings []models.Finding

	for _, rule := range s.rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}

		if s.isProjectScopedRule(rule) {
			projectScopedRules = append(projectScopedRules, rule)
			continue
		}

		for _, pat := range rule.Patterns {
			if pat.Type == "file-exists" {
				directFindings := s.checkFileExists(rule, pat, project.RootPath)
				for _, f := range directFindings {
					findings = append(findings, f)
					emit(f)
				}
				continue
			}
			if pat.Target == "" {
				continue
			}
			targetToRules[pat.Target] = append(targetToRules[pat.Target], rule)
		}
	}

	fileToRules := make(map[string][]config.RuleDefinition)
	var allFiles []string
	seenFiles := make(map[string]bool)

	for target, rules := range targetToRules {
		files := s.resolveCachedFiles(target, project.RootPath)
		for _, f := range files {
			fileToRules[f] = append(fileToRules[f], rules...)
			if !seenFiles[f] {
				seenFiles[f] = true
				allFiles = append(allFiles, f)
			}
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	numWorkers := runtime.NumCPU() * 2
	fileChan := make(chan string, len(allFiles))
	for _, f := range allFiles {
		fileChan <- f
	}
	close(fileChan)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fpath := range fileChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				fileFindings := s.scanFile(fpath, fileToRules[fpath], project.RootPath)
				if len(fileFindings) > 0 {
					mu.Lock()
					findings = append(findings, fileFindings...)
					for _, f := range fileFindings {
						emit(f)
					}
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	for _, rule := range projectScopedRules {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		ruleFindings := s.scanProjectScopedRule(rule, project.RootPath)
		if len(ruleFindings) == 0 {
			continue
		}
		findings = append(findings, ruleFindings...)
		for _, f := range ruleFindings {
			emit(f)
		}
	}

	return findings, ctx.Err()
}

func (s *RulesScanner) scanFile(fpath string, rules []config.RuleDefinition, root string) []models.Finding {
	fc, err := s.loadFileContent(fpath)
	if err != nil {
		return nil
	}

	var findings []models.Finding
	rel, _ := filepath.Rel(root, fpath)

	uniqueRules := make(map[string]config.RuleDefinition)
	for _, r := range rules {
		uniqueRules[r.ID] = r
	}

	for _, rule := range uniqueRules {
		findings = append(findings, s.evaluateRule(rule, fc, fpath, rel)...)
	}

	return findings
}

func (s *RulesScanner) loadFileContent(fpath string) (*fileContent, error) {
	info, err := os.Stat(fpath)
	if err != nil || info.IsDir() || info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file cannot be scanned")
	}

	data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	text := string(data)
	return &fileContent{
		data:  data,
		text:  text,
		lines: strings.Split(text, "\n"),
	}, nil
}

func (s *RulesScanner) evaluateRule(rule config.RuleDefinition, fc *fileContent, fpath, rel string) []models.Finding {
	var findings []models.Finding
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "any"
	}

	if condition == "all" {
		var evidences []models.Finding
		for _, pat := range rule.Patterns {
			if !patternAppliesToFile(pat, rel) {
				return nil
			}

			pf := s.evaluatePattern(rule, pat, fc, fpath, rel)
			if len(pf) == 0 {
				return nil
			}
			evidences = append(evidences, pf[0])
		}

		primary := pickPrimaryFinding(evidences)
		if primary != nil {
			findings = append(findings, *primary)
		}
	} else {
		seen := make(map[string]bool)
		for _, pat := range rule.Patterns {
			if !patternAppliesToFile(pat, rel) {
				continue
			}

			pf := s.evaluatePattern(rule, pat, fc, fpath, rel)
			for _, f := range pf {
				key := fmt.Sprintf("%d|%s", f.Line, f.CodeSnippet)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func pickPrimaryFinding(findings []models.Finding) *models.Finding {
	if len(findings) == 0 {
		return nil
	}

	for i := range findings {
		if findings[i].Line > 0 {
			return &findings[i]
		}
	}

	return &findings[0]
}

func (s *RulesScanner) isProjectScopedRule(rule config.RuleDefinition) bool {
	if len(rule.Patterns) == 0 {
		return false
	}

	targets := make(map[string]bool)
	hasScannablePattern := false
	allProjectScoped := true

	for _, pat := range rule.Patterns {
		if pat.Type == "file-exists" {
			return false
		}
		target := strings.ToLower(strings.TrimSpace(pat.Target))
		if target == "" {
			continue
		}

		targets[target] = true
		hasScannablePattern = true
		if s.patternScope(rule, pat) != "project" {
			allProjectScoped = false
		}
	}

	if len(targets) > 1 {
		return true
	}

	if !hasScannablePattern {
		return false
	}

	return allProjectScoped
}

func (s *RulesScanner) patternScope(rule config.RuleDefinition, pat config.PatternDef) string {
	scope := strings.ToLower(strings.TrimSpace(pat.Scope))
	switch scope {
	case "project", "global":
		return "project"
	case "file":
		return "file"
	}

	target := strings.ToLower(strings.TrimSpace(pat.Target))
	if pat.Negative && len(rule.Patterns) == 1 && defaultProjectScopedTarget(target) {
		return "project"
	}

	return "file"
}

func defaultProjectScopedTarget(target string) bool {
	switch target {
	case "middleware-files", "config-files", "env-files", "composer-files", "routes-files":
		return true
	default:
		return false
	}
}

func (s *RulesScanner) scanProjectScopedRule(rule config.RuleDefinition, root string) []models.Finding {
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "any"
	}

	var evidences []ruleEvidence
	for _, pat := range rule.Patterns {
		if pat.Type == "file-exists" || strings.TrimSpace(pat.Target) == "" {
			continue
		}

		evidence, ok := s.evaluatePatternAcrossProject(rule, pat, root)
		if condition == "all" {
			if !ok {
				return nil
			}
			evidences = append(evidences, evidence)
			continue
		}

		if ok {
			evidences = append(evidences, evidence)
		}
	}

	if len(evidences) == 0 {
		return nil
	}

	if condition == "all" {
		primary := pickPrimaryEvidence(evidences)
		return []models.Finding{s.buildFinding(rule, primary.file, primary.line, primary.snippet, primary.lines, primary.lineIdx)}
	}

	seen := make(map[string]bool)
	var findings []models.Finding
	for _, ev := range evidences {
		key := fmt.Sprintf("%s|%d|%s", ev.file, ev.line, ev.snippet)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, s.buildFinding(rule, ev.file, ev.line, ev.snippet, ev.lines, ev.lineIdx))
	}

	return findings
}

func pickPrimaryEvidence(evidences []ruleEvidence) ruleEvidence {
	for _, ev := range evidences {
		if ev.line > 0 {
			return ev
		}
	}
	return evidences[0]
}

func (s *RulesScanner) evaluatePatternAcrossProject(rule config.RuleDefinition, pat config.PatternDef, root string) (ruleEvidence, bool) {
	files := s.resolveCachedFiles(pat.Target, root)
	if len(files) == 0 {
		return ruleEvidence{}, false
	}

	basePat := pat
	basePat.Negative = false

	for _, fpath := range files {
		fc, err := s.loadFileContent(fpath)
		if err != nil {
			continue
		}

		rel, _ := filepath.Rel(root, fpath)
		pf := s.evaluatePattern(rule, basePat, fc, fpath, rel)
		if len(pf) == 0 {
			continue
		}

		if pat.Negative {
			return ruleEvidence{}, false
		}

		f := pf[0]
		return ruleEvidence{
			file:    f.File,
			line:    f.Line,
			snippet: f.CodeSnippet,
			lines:   append([]string{}, fc.lines...),
			lineIdx: f.Line - 1,
		}, true
	}

	if pat.Negative {
		return ruleEvidence{
			file:    projectScopeLocation(pat.Target, files, root),
			line:    0,
			snippet: "[PATTERN NOT FOUND]",
			lineIdx: -1,
		}, true
	}

	return ruleEvidence{}, false
}

func projectScopeLocation(target string, files []string, root string) string {
	if len(files) == 0 {
		return target
	}

	rel, err := filepath.Rel(root, files[0])
	if err != nil {
		return target
	}

	if len(files) == 1 {
		return filepath.ToSlash(rel)
	}

	dir := filepath.Dir(rel)
	if dir == "." || dir == "" {
		return filepath.ToSlash(rel)
	}

	return filepath.ToSlash(dir)
}

func (s *RulesScanner) evaluatePattern(rule config.RuleDefinition, pat config.PatternDef, fc *fileContent, fpath, rel string) []models.Finding {
	switch pat.Type {
	case "regex", "contains":
		return s.checkLineContent(rule, pat, fc, fpath, rel)
	case "regex-multiline":
		return s.checkMultilineContent(rule, pat, fc, fpath, rel)
	case "entropy":
		return s.checkEntropy(rule, pat, fc, rel)
	default:
		return nil
	}
}

func (s *RulesScanner) checkFileExists(rule config.RuleDefinition, pat config.PatternDef, root string) []models.Finding {
	candidate := strings.TrimSpace(pat.Pattern)
	if candidate == "" {
		candidate = strings.TrimSpace(pat.Target)
	}
	if candidate == "" {
		return nil
	}

	filePath := candidate
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(root, filePath)
	}
	filePath = filepath.Clean(filePath)

	info, err := os.Stat(filePath)
	exists := err == nil && !info.IsDir()

	matched := exists
	snippet := "[FILE EXISTS]"
	if pat.Negative {
		matched = !exists
		snippet = "[FILE NOT FOUND]"
	}
	if !matched {
		return nil
	}

	rel := candidate
	if filepath.IsAbs(filePath) {
		if relPath, relErr := filepath.Rel(root, filePath); relErr == nil {
			rel = relPath
		} else {
			rel = filePath
		}
	}

	return []models.Finding{s.buildFinding(rule, filepath.ToSlash(rel), 0, snippet, nil, 0)}
}

func (s *RulesScanner) checkLineContent(rule config.RuleDefinition, pat config.PatternDef, fc *fileContent, fpath, rel string) []models.Finding {
	re := s.reCache[pat.Pattern]
	exRe := s.reCache[pat.ExcludePattern]
	if exRe != nil && exRe.MatchString(filepath.ToSlash(fpath)) {
		return nil
	}

	var findings []models.Finding
	matched := false

	for i, line := range fc.lines {
		if isLikelyCommentLine(line) {
			continue
		}

		isMatch := false
		if pat.Type == "contains" {
			isMatch = strings.Contains(line, pat.Pattern)
		} else if re != nil {
			isMatch = re.MatchString(line)
		}

		if isMatch {
			if exRe != nil {
				window := buildLineWindow(fc.lines, i, 6)
				if exRe.MatchString(line) || exRe.MatchString(window) {
					continue
				}

				if strings.ToLower(strings.TrimSpace(pat.Scope)) == "project" && exRe.Match(fc.data) {
					continue
				}
			}
			matched = true
			if !pat.Negative {
				findings = append(findings, s.buildFinding(rule, rel, i+1, strings.TrimSpace(line), fc.lines, i))
			}
		}
	}

	if pat.Negative && !matched {
		findings = append(findings, s.buildFinding(rule, rel, 0, "[PATTERN NOT FOUND]", nil, 0))
	}

	return findings
}

func (s *RulesScanner) checkMultilineContent(rule config.RuleDefinition, pat config.PatternDef, fc *fileContent, fpath, rel string) []models.Finding {
	re := s.reCache[pat.Pattern]
	if re == nil {
		return nil
	}

	exRe := s.reCache[pat.ExcludePattern]
	if exRe != nil {
		if exRe.Match(fc.data) || exRe.MatchString(filepath.ToSlash(fpath)) {
			return nil
		}
	}

	indexes := re.FindAllStringIndex(fc.text, -1)
	if len(indexes) == 0 {
		if pat.Negative {
			return []models.Finding{s.buildFinding(rule, rel, 0, "[PATTERN NOT FOUND]", nil, 0)}
		}
		return nil
	}
	if pat.Negative {
		return nil
	}

	var findings []models.Finding
	for _, loc := range indexes {
		start := loc[0]
		lineNum := 1 + strings.Count(fc.text[:start], "\n")

		text := "[MULTI-LINE MATCH]"
		if lineNum-1 < len(fc.lines) {
			text = strings.TrimSpace(fc.lines[lineNum-1])
		}

		findings = append(findings, s.buildFinding(rule, rel, lineNum, text, fc.lines, lineNum-1))
	}

	return findings
}

func (s *RulesScanner) checkEntropy(rule config.RuleDefinition, pat config.PatternDef, fc *fileContent, rel string) []models.Finding {
	threshold := 4.5
	if pat.Pattern != "" {
		fmt.Sscanf(pat.Pattern, "%f", &threshold)
	}

	var findings []models.Finding
	matched := false
	for i, line := range fc.lines {
		words := strings.FieldsFunc(line, func(r rune) bool {
			return r == '"' || r == '\'' || r == ' ' || r == '=' || r == ':'
		})
		for _, word := range words {
			if len(word) > 16 && calculateEntropy(word) > threshold {
				matched = true
				if !pat.Negative {
					findings = append(findings, s.buildFinding(rule, rel, i+1, strings.TrimSpace(line), fc.lines, i))
				}
				break
			}
		}
	}
	if pat.Negative && !matched {
		findings = append(findings, s.buildFinding(rule, rel, 0, "[PATTERN NOT FOUND]", nil, 0))
	}
	return findings
}

func (s *RulesScanner) resolveCachedFiles(target, root string) []string {
	s.cacheMu.RLock()
	if files, ok := s.targetFiles[target]; ok {
		s.cacheMu.RUnlock()
		return files
	}
	s.cacheMu.RUnlock()

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	files := resolveTarget(target, root)
	s.targetFiles[target] = files
	return files
}

func (s *RulesScanner) buildFinding(rule config.RuleDefinition, file string, line int, snippet string, lines []string, lineIdx int) models.Finding {
	var before, after []string
	if lines != nil && lineIdx >= 0 {
		before = getContext(lines, lineIdx, -3, -1)
		after = getContext(lines, lineIdx, 1, 3)
	}

	cwe := normalizeRuleCWE(rule.CWE, rule.Tags)
	owasp := normalizeRuleOWASP(rule.OWASP, rule.Tags)

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
		CWE:           cwe,
		OWASP:         owasp,
		Confidence:    rule.Confidence,
		CVSSScore:     rule.CVSSv3.Score,
		CVSSVector:    rule.CVSSv3.Vector,
	}
}

func normalizeRuleCWE(cwe string, tags []string) string {
	cwe = strings.TrimSpace(cwe)
	if cwe != "" {
		return strings.ToUpper(cwe)
	}
	for _, tag := range tags {
		t := strings.TrimSpace(strings.ToUpper(tag))
		if strings.HasPrefix(t, "CWE-") {
			return t
		}
	}
	return ""
}

func normalizeRuleOWASP(owasp string, tags []string) string {
	owasp = strings.TrimSpace(strings.ToUpper(owasp))
	if owasp != "" {
		return owasp
	}

	for _, tag := range tags {
		t := strings.TrimSpace(strings.ToUpper(tag))
		if strings.Contains(t, "OWASP-") {
			return t
		}
		if strings.HasPrefix(t, "A0") || strings.HasPrefix(t, "A1") {
			return t
		}
	}
	return ""
}

func resolveTarget(target, root string) []string {
	if target == "any" {
		return resolveAnyTarget(root)
	}

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

func resolveAnyTarget(root string) []string {
	var files []string
	seen := make(map[string]bool)

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isReservedRulesDir(path, root) {
				return filepath.SkipDir
			}
			if skipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > MaxFileSize {
			return nil
		}

		if !isAnyTargetFile(path) {
			return nil
		}
		if seen[path] {
			return nil
		}
		seen[path] = true
		files = append(files, path)
		return nil
	})

	return files
}

func isReservedRulesDir(path, root string) bool {
	cleaned := filepath.Clean(path)
	return samePath(cleaned, filepath.Join(root, "rules")) ||
		samePath(cleaned, filepath.Join(root, "vanguard-rules")) ||
		samePath(cleaned, filepath.Join(root, ".vanguard-rules"))
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func isAnyTargetFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(name, ".env.") {
		return true
	}

	switch name {
	case ".env",
		"composer.json", "composer.lock",
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"phpunit.xml", "phpunit.xml.dist", ".htaccess":
		return true
	}

	lowerPath := strings.ToLower(path)
	if strings.HasSuffix(lowerPath, ".blade.php") {
		return true
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".js", ".ts", ".jsx", ".tsx", ".twig", ".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".lock", ".sql", ".toml":
		return true
	default:
		return false
	}
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
		// Keep PHP source scanning focused on executable PHP files.
		// Blade templates are handled by the dedicated blade-files target.
		return strings.HasSuffix(path, ".php") && !strings.HasSuffix(path, ".blade.php")
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... (%d chars)", len(s))
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

func getContext(lines []string, center int, startRel, endRel int) []string {
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

func isLikelyCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	switch {
	case strings.HasPrefix(trimmed, "//"),
		strings.HasPrefix(trimmed, "#"),
		strings.HasPrefix(trimmed, "/*"),
		strings.HasPrefix(trimmed, "*"),
		strings.HasPrefix(trimmed, "*/"),
		strings.HasPrefix(trimmed, "<!--"):
		return true
	default:
		return false
	}
}

func buildLineWindow(lines []string, center, radius int) string {
	if len(lines) == 0 {
		return ""
	}
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius
	if end >= len(lines) {
		end = len(lines) - 1
	}

	return strings.Join(lines[start:end+1], "\n")
}

func patternAppliesToFile(pat config.PatternDef, relPath string) bool {
	target := strings.ToLower(strings.TrimSpace(pat.Target))
	if target == "" || target == "any" {
		return true
	}

	rel := strings.TrimPrefix(filepath.ToSlash(relPath), "./")
	relLower := strings.ToLower(rel)
	baseLower := strings.ToLower(filepath.Base(rel))

	switch target {
	case "php-files":
		return strings.HasSuffix(relLower, ".php") && !strings.HasSuffix(relLower, ".blade.php")
	case "blade-files":
		return strings.HasSuffix(relLower, ".blade.php")
	case "twig-files":
		return strings.HasSuffix(relLower, ".twig")
	case "config-files":
		return (strings.HasPrefix(relLower, "config/") ||
			strings.HasPrefix(relLower, "application/config/") ||
			strings.HasPrefix(relLower, "app/config/")) &&
			(strings.HasSuffix(relLower, ".php") || strings.HasSuffix(relLower, ".yaml") ||
				strings.HasSuffix(relLower, ".yml") || strings.HasSuffix(relLower, ".xml"))
	case "env-files":
		return baseLower == ".env" || strings.HasPrefix(baseLower, ".env.")
	case "routes-files":
		return strings.HasPrefix(relLower, "routes/") && strings.HasSuffix(relLower, ".php")
	case "migration-files":
		return strings.HasPrefix(relLower, "database/migrations/") && strings.HasSuffix(relLower, ".php")
	case "js-files":
		return strings.HasPrefix(relLower, "resources/js/") &&
			(strings.HasSuffix(relLower, ".js") || strings.HasSuffix(relLower, ".ts") ||
				strings.HasSuffix(relLower, ".jsx") || strings.HasSuffix(relLower, ".tsx"))
	case "composer-files":
		return baseLower == "composer.json" || baseLower == "composer.lock"
	case "middleware-files":
		return strings.HasPrefix(relLower, "app/http/middleware/") && strings.HasSuffix(relLower, ".php")
	case "model-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/models/") ||
				(strings.HasPrefix(relLower, "app/") && strings.Count(relLower, "/") == 1))
	case "service-files":
		return strings.HasPrefix(relLower, "app/services/") && strings.HasSuffix(relLower, ".php")
	case "controller-files":
		return strings.HasPrefix(relLower, "app/http/controllers/") && strings.HasSuffix(relLower, ".php")
	case "request-files":
		return strings.HasPrefix(relLower, "app/http/requests/") && strings.HasSuffix(relLower, ".php")
	default:
		if strings.ContainsAny(target, "*?[") {
			ok, err := filepath.Match(filepath.FromSlash(target), filepath.FromSlash(rel))
			return err == nil && ok
		}

		target = strings.TrimPrefix(filepath.ToSlash(target), "./")
		return strings.EqualFold(rel, target) || strings.HasSuffix(relLower, "/"+strings.ToLower(target))
	}
}
