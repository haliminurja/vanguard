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

	"github.com/haliminurja/vanguard/internal/config"
	"github.com/haliminurja/vanguard/internal/models"
)

const (
	MaxFileSize  = 5 * 1024 * 1024
	RegexTimeout = 2 * time.Second
)

var (
	entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9_+/=-]{20,}`)
	uuidLikePattern         = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	hexOnlyPattern          = regexp.MustCompile(`(?i)^[a-f0-9]+$`)
)

type fileContent struct {
	data      []byte
	text      string
	codeText  string
	lines     []string
	codeLines []string
}

type commentStripState struct {
	inBlock bool
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
	if isLikelyBinaryContent(data) {
		return nil, fmt.Errorf("binary file is not scannable")
	}

	text := string(data)
	lines := strings.Split(text, "\n")
	codeLines := stripComments(lines)
	return &fileContent{
		data:      data,
		text:      text,
		codeText:  strings.Join(codeLines, "\n"),
		lines:     lines,
		codeLines: codeLines,
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
	if excludeMatchesPath(exRe, fpath) {
		return nil
	}

	var findings []models.Finding
	seen := make(map[string]bool)
	matched := false

	addFinding := func(lineNum int, lineIdx int, fallback string) {
		snippet := strings.TrimSpace(fallback)
		if snippet == "" && lineIdx >= 0 && lineIdx < len(fc.codeLines) {
			snippet = strings.TrimSpace(fc.codeLines[lineIdx])
		}
		key := fmt.Sprintf("%d|%s", lineNum, snippet)
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, s.buildFinding(rule, rel, lineNum, snippet, fc.lines, lineIdx))
	}

	for i, line := range fc.codeLines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		isMatch := false
		if pat.Type == "contains" {
			isMatch = strings.Contains(line, pat.Pattern)
		} else if re != nil {
			isMatch = re.MatchString(line)
		}

		if isMatch {
			if matchExcluded(pat, exRe, fc, i, i, line, 6) {
				continue
			}
			matched = true
			if !pat.Negative {
				fallback := line
				if i < len(fc.lines) {
					fallback = fc.lines[i]
				}
				addFinding(i+1, i, fallback)
			}
		}
	}

	if pat.Type == "regex" && re != nil {
		indexes := re.FindAllStringIndex(fc.codeText, -1)
		for _, loc := range indexes {
			startLine := 1 + strings.Count(fc.codeText[:loc[0]], "\n")
			endLine := startLine + strings.Count(fc.codeText[loc[0]:loc[1]], "\n")
			lineIdx := startLine - 1

			matchText := fc.codeText[loc[0]:loc[1]]
			if matchExcluded(pat, exRe, fc, lineIdx, endLine-1, matchText, 6) {
				continue
			}

			matched = true
			if !pat.Negative {
				fallback := fc.codeText[loc[0]:loc[1]]
				if lineIdx >= 0 && lineIdx < len(fc.lines) {
					fallback = fc.lines[lineIdx]
				}
				addFinding(startLine, lineIdx, fallback)
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
	if excludeMatchesPath(exRe, fpath) {
		return nil
	}

	indexes := re.FindAllStringIndex(fc.codeText, -1)
	var findings []models.Finding
	matched := false
	for _, loc := range indexes {
		start := loc[0]
		lineNum := 1 + strings.Count(fc.codeText[:start], "\n")
		endLine := lineNum + strings.Count(fc.codeText[loc[0]:loc[1]], "\n")
		lineIdx := lineNum - 1
		matchText := fc.codeText[loc[0]:loc[1]]

		if matchExcluded(pat, exRe, fc, lineIdx, endLine-1, matchText, 0) {
			continue
		}

		matched = true
		if pat.Negative {
			return nil
		}

		text := "[MULTI-LINE MATCH]"
		if lineIdx >= 0 && lineIdx < len(fc.lines) {
			text = strings.TrimSpace(fc.lines[lineIdx])
		}

		findings = append(findings, s.buildFinding(rule, rel, lineNum, text, fc.lines, lineIdx))
	}

	if pat.Negative && !matched {
		return []models.Finding{s.buildFinding(rule, rel, 0, "[PATTERN NOT FOUND]", nil, 0)}
	}
	if !matched {
		return nil
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
	for i, line := range fc.codeLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if containsPlaceholderToken(line) {
			continue
		}

		words := entropyCandidatePattern.FindAllString(line, -1)
		for _, word := range words {
			if !isLikelySecretToken(word, line) {
				continue
			}
			if calculateEntropy(word) > threshold {
				matched = true
				if !pat.Negative {
					snippet := strings.TrimSpace(fc.lines[i])
					if snippet == "" {
						snippet = strings.TrimSpace(line)
					}
					findings = append(findings, s.buildFinding(rule, rel, i+1, snippet, fc.lines, i))
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
		if strings.Contains(filepath.ToSlash(pat), "**") {
			collectRecursiveGlob(root, pat, seen, &files)
			continue
		}

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
			walkRoots = []string{
				filepath.Join(root, "resources", "views"),
				filepath.Join(root, "modules"),
				root,
			}
		case "twig-files":
			walkRoots = []string{
				filepath.Join(root, "templates"),
				filepath.Join(root, "views"),
				root,
			}
		case "js-files":
			walkRoots = []string{
				filepath.Join(root, "resources", "js"),
				filepath.Join(root, "assets", "js"),
				filepath.Join(root, "public", "js"),
				filepath.Join(root, "src"),
				filepath.Join(root, "webroot", "js"),
				root,
			}
		case "config-files":
			walkRoots = []string{
				filepath.Join(root, "config"),
				filepath.Join(root, "application", "config"),
				filepath.Join(root, "app", "Config"),
			}
		case "routes-files":
			walkRoots = []string{
				filepath.Join(root, "routes"),
				filepath.Join(root, "app", "Config"),
				filepath.Join(root, "application", "config"),
			}
		case "migration-files":
			walkRoots = []string{filepath.Join(root, "database", "migrations")}
		case "middleware-files":
			walkRoots = []string{
				filepath.Join(root, "app", "Http", "Middleware"),
				filepath.Join(root, "src", "Middleware"),
				filepath.Join(root, "config", "Middleware"),
			}
		case "model-files":
			walkRoots = []string{
				filepath.Join(root, "app", "Models"),
				filepath.Join(root, "app"),
				filepath.Join(root, "src", "Model"),
				filepath.Join(root, "src", "Model", "Entity"),
				filepath.Join(root, "src", "Model", "Table"),
				filepath.Join(root, "application", "models"),
				filepath.Join(root, "models"),
			}
		case "service-files":
			walkRoots = []string{
				filepath.Join(root, "app", "Services"),
				filepath.Join(root, "src", "Service"),
				filepath.Join(root, "services"),
			}
		case "controller-files":
			walkRoots = []string{
				filepath.Join(root, "app", "Http", "Controllers"),
				filepath.Join(root, "src", "Controller"),
				filepath.Join(root, "application", "controllers"),
				filepath.Join(root, "controllers"),
			}
		case "request-files":
			walkRoots = []string{
				filepath.Join(root, "app", "Http", "Requests"),
				filepath.Join(root, "src", "Request"),
				filepath.Join(root, "requests"),
			}
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

func collectRecursiveGlob(root, pattern string, seen map[string]bool, files *[]string) {
	relPattern, err := filepath.Rel(root, pattern)
	if err != nil {
		return
	}
	relPattern = filepath.ToSlash(strings.TrimPrefix(relPattern, "./"))
	walkRoot := recursiveGlobWalkRoot(root, relPattern)

	_ = filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > MaxFileSize {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if !matchGlobPattern(relPattern, rel) {
			return nil
		}
		if seen[path] {
			return nil
		}
		seen[path] = true
		*files = append(*files, path)
		return nil
	})
}

func recursiveGlobWalkRoot(root, pattern string) string {
	parts := strings.Split(filepath.ToSlash(pattern), "/")
	fixed := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.ContainsAny(part, "*?[") {
			break
		}
		if part == "" || part == "." {
			continue
		}
		fixed = append(fixed, part)
	}
	if len(fixed) == 0 {
		return root
	}
	segments := append([]string{root}, fixed...)
	return filepath.Join(segments...)
}

func matchGlobPattern(pattern, rel string) bool {
	pattern = filepath.ToSlash(strings.TrimPrefix(pattern, "./"))
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))

	if !strings.Contains(pattern, "**") {
		ok, err := filepath.Match(filepath.FromSlash(pattern), filepath.FromSlash(rel))
		return err == nil && ok
	}

	re, err := regexp.Compile(globToRegex(pattern))
	return err == nil && re.MatchString(rel)
}

func globToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					b.WriteString("(?:.*/)?")
					i++
				} else {
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end >= 0 {
				class := pattern[i : i+end+2]
				if strings.HasPrefix(class, "[!") {
					class = "[^" + class[2:]
				}
				b.WriteString(class)
				i += end + 1
			} else {
				b.WriteString(regexp.QuoteMeta(string(ch)))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}

	b.WriteString("$")
	return b.String()
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
	case ".php", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".twig", ".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".lock", ".sql", ".toml":
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
		return []string{
			filepath.Join(root, "templates", "*.twig"),
			filepath.Join(root, "views", "*.twig"),
		}
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
		return []string{
			filepath.Join(root, "routes", "*.php"),
			filepath.Join(root, "app", "Config", "Routes.php"),
			filepath.Join(root, "application", "config", "routes.php"),
		}
	case "migration-files":
		return []string{filepath.Join(root, "database", "migrations", "*.php")}
	case "js-files":
		return []string{
			filepath.Join(root, "resources", "js", "*.js"),
			filepath.Join(root, "resources", "js", "*.ts"),
			filepath.Join(root, "assets", "js", "*.js"),
			filepath.Join(root, "assets", "js", "*.ts"),
			filepath.Join(root, "public", "js", "*.js"),
			filepath.Join(root, "public", "js", "*.ts"),
			filepath.Join(root, "*.js"),
			filepath.Join(root, "*.ts"),
			filepath.Join(root, "*.mjs"),
			filepath.Join(root, "*.cjs"),
		}
	case "composer-files":
		return []string{filepath.Join(root, "composer.json"), filepath.Join(root, "composer.lock")}
	case "middleware-files":
		return []string{
			filepath.Join(root, "app", "Http", "Middleware", "*.php"),
			filepath.Join(root, "src", "Middleware", "*.php"),
			filepath.Join(root, "config", "Middleware", "*.php"),
		}
	case "model-files":
		return []string{
			filepath.Join(root, "app", "Models", "*.php"),
			filepath.Join(root, "app", "*.php"),
			filepath.Join(root, "src", "Model", "*.php"),
			filepath.Join(root, "src", "Model", "Entity", "*.php"),
			filepath.Join(root, "src", "Model", "Table", "*.php"),
			filepath.Join(root, "application", "models", "*.php"),
			filepath.Join(root, "models", "*.php"),
		}
	case "service-files":
		return []string{
			filepath.Join(root, "app", "Services", "*.php"),
			filepath.Join(root, "src", "Service", "*.php"),
			filepath.Join(root, "services", "*.php"),
		}
	case "controller-files":
		return []string{
			filepath.Join(root, "app", "Http", "Controllers", "*.php"),
			filepath.Join(root, "src", "Controller", "*.php"),
			filepath.Join(root, "application", "controllers", "*.php"),
			filepath.Join(root, "controllers", "*.php"),
		}
	case "request-files":
		return []string{
			filepath.Join(root, "app", "Http", "Requests", "*.php"),
			filepath.Join(root, "src", "Request", "*.php"),
			filepath.Join(root, "requests", "*.php"),
		}
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
		return []string{".php", ".yaml", ".yml", ".xml", ".json", ".ini", ".conf", ".toml"}
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
			strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".tsx") ||
			strings.HasSuffix(path, ".mjs") || strings.HasSuffix(path, ".cjs")
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

func stripComments(lines []string) []string {
	sanitized := make([]string, len(lines))
	state := &commentStripState{}
	for i, line := range lines {
		sanitized[i] = stripCommentsFromLine(line, state)
	}
	return sanitized
}

func stripCommentsFromLine(line string, state *commentStripState) string {
	if line == "" {
		return ""
	}

	var out strings.Builder
	out.Grow(len(line))

	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		next := byte(0)
		if i+1 < len(line) {
			next = line[i+1]
		}

		if state.inBlock {
			if ch == '*' && next == '/' {
				state.inBlock = false
				i++
			}
			continue
		}

		if escaped {
			out.WriteByte(ch)
			escaped = false
			continue
		}

		if (inSingle || inDouble) && ch == '\\' {
			out.WriteByte(ch)
			escaped = true
			continue
		}

		if !inDouble && ch == '\'' {
			inSingle = !inSingle
			out.WriteByte(ch)
			continue
		}
		if !inSingle && ch == '"' {
			inDouble = !inDouble
			out.WriteByte(ch)
			continue
		}

		if !inSingle && !inDouble {
			if ch == '/' && next == '/' {
				break
			}
			if ch == '#' {
				break
			}
			if ch == '/' && next == '*' {
				state.inBlock = true
				i++
				continue
			}
		}

		out.WriteByte(ch)
	}

	return out.String()
}

func isLikelyBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}

	nonPrintable := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(len(sample)) > 0.30
}

func containsPlaceholderToken(line string) bool {
	lower := strings.ToLower(line)
	placeholders := []string{
		"example", "placeholder", "replace_me", "changeme", "dummy", "sample", "fake", "lorem",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isLikelySecretToken(token, line string) bool {
	token = strings.TrimSpace(strings.Trim(token, `"'`))
	if len(token) < 20 {
		return false
	}

	lowerToken := strings.ToLower(token)
	if strings.HasPrefix(lowerToken, "http://") || strings.HasPrefix(lowerToken, "https://") {
		return false
	}
	if uuidLikePattern.MatchString(token) {
		return false
	}

	if hexOnlyPattern.MatchString(token) {
		switch len(token) {
		case 32, 40, 64, 96, 128:
			if isLikelyHashContext(line) && !containsSecretHint(line) {
				return false
			}
		}
	}

	classCount := countCharacterClasses(token)
	if classCount < 2 {
		return false
	}
	if classCount < 3 && !containsSecretHint(line) {
		return false
	}

	if strings.Count(token, "_") > len(token)/3 {
		return false
	}

	return true
}

func countCharacterClasses(s string) int {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	count := 0
	if hasLower {
		count++
	}
	if hasUpper {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSymbol {
		count++
	}
	return count
}

func isLikelyHashContext(line string) bool {
	lower := strings.ToLower(line)
	keywords := []string{"sha1", "sha256", "sha384", "sha512", "md5", "hash", "checksum", "digest", "fingerprint"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func containsSecretHint(line string) bool {
	lower := strings.ToLower(line)
	keywords := []string{"secret", "token", "api_key", "apikey", "access_key", "password", "passwd", "bearer", "private", "credential", "jwt"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
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

func buildRangeWindow(lines []string, start, end, pad int) string {
	if len(lines) == 0 {
		return ""
	}
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}

	start -= pad
	if start < 0 {
		start = 0
	}
	end += pad
	if end >= len(lines) {
		end = len(lines) - 1
	}

	return strings.Join(lines[start:end+1], "\n")
}

func excludeMatchesPath(exRe *regexp.Regexp, fpath string) bool {
	if exRe == nil {
		return false
	}
	return exRe.MatchString(filepath.ToSlash(fpath))
}

func matchExcluded(pat config.PatternDef, exRe *regexp.Regexp, fc *fileContent, startLine, endLine int, matchText string, pad int) bool {
	if exRe == nil {
		return false
	}
	if exRe.MatchString(matchText) {
		return true
	}

	window := buildRangeWindow(fc.codeLines, startLine, endLine, pad)
	if exRe.MatchString(window) {
		return true
	}

	if strings.ToLower(strings.TrimSpace(pat.Scope)) == "project" && exRe.MatchString(fc.codeText) {
		return true
	}

	return false
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
				strings.HasSuffix(relLower, ".yml") || strings.HasSuffix(relLower, ".xml") ||
				strings.HasSuffix(relLower, ".json") || strings.HasSuffix(relLower, ".ini") ||
				strings.HasSuffix(relLower, ".conf") || strings.HasSuffix(relLower, ".toml"))
	case "env-files":
		return baseLower == ".env" || strings.HasPrefix(baseLower, ".env.")
	case "routes-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "routes/") ||
				relLower == "routes.php" ||
				strings.HasSuffix(relLower, "/routes.php"))
	case "migration-files":
		return strings.HasPrefix(relLower, "database/migrations/") && strings.HasSuffix(relLower, ".php")
	case "js-files":
		return strings.HasSuffix(relLower, ".js") || strings.HasSuffix(relLower, ".ts") ||
			strings.HasSuffix(relLower, ".jsx") || strings.HasSuffix(relLower, ".tsx") ||
			strings.HasSuffix(relLower, ".mjs") || strings.HasSuffix(relLower, ".cjs")
	case "composer-files":
		return baseLower == "composer.json" || baseLower == "composer.lock"
	case "middleware-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/http/middleware/") ||
				strings.HasPrefix(relLower, "src/middleware/") ||
				strings.HasPrefix(relLower, "config/middleware/"))
	case "model-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/models/") ||
				(strings.HasPrefix(relLower, "app/") && strings.Count(relLower, "/") == 1) ||
				strings.HasPrefix(relLower, "src/model/") ||
				strings.HasPrefix(relLower, "application/models/") ||
				strings.HasPrefix(relLower, "models/"))
	case "service-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/services/") ||
				strings.HasPrefix(relLower, "src/service/") ||
				strings.HasPrefix(relLower, "services/"))
	case "controller-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/http/controllers/") ||
				strings.HasPrefix(relLower, "src/controller/") ||
				strings.HasPrefix(relLower, "application/controllers/") ||
				strings.HasPrefix(relLower, "controllers/"))
	case "request-files":
		return strings.HasSuffix(relLower, ".php") &&
			(strings.HasPrefix(relLower, "app/http/requests/") ||
				strings.HasPrefix(relLower, "src/request/") ||
				strings.HasPrefix(relLower, "requests/"))
	default:
		if strings.ContainsAny(target, "*?[") {
			return matchGlobPattern(target, rel)
		}

		target = strings.TrimPrefix(filepath.ToSlash(target), "./")
		return strings.EqualFold(rel, target) || strings.HasSuffix(relLower, "/"+strings.ToLower(target))
	}
}
