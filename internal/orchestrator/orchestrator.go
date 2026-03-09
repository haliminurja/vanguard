package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vanguard/internal/config"
	"vanguard/internal/eventbus"
	"vanguard/internal/models"
	"vanguard/internal/provider"
	"vanguard/internal/reporter"
	"vanguard/internal/resolver"
	"vanguard/internal/scanner"
	depscanner "vanguard/internal/scanner"
	"vanguard/internal/store"
)

type Orchestrator struct {
	bus     *eventbus.EventBus
	cfg     *config.Config
	target  string
	version string
}

func New(bus *eventbus.EventBus, cfg *config.Config, target string, version string) *Orchestrator {
	return &Orchestrator{bus: bus, cfg: cfg, target: target, version: version}
}
func (o *Orchestrator) Run(ctx context.Context) error {
	startTime := time.Now()

	scanners := []models.Scanner{
		depscanner.New(),
	}

	scanner.SetExtraSkipDirs(o.cfg.Scanners.IgnoreDirs)

	scanners = o.filterScanners(scanners)

	o.bus.Publish(eventbus.NewEvent(eventbus.EventScanStarted, eventbus.ScanStartedData{
		ProjectPath:  o.target,
		ProjectName:  o.target,
		ScannerCount: len(scanners),
	}))
	o.stageStart(models.StageProvider)

	var src provider.SourceProvider
	if provider.IsGitURL(o.target) {
		src = provider.NewGitProvider(o.cfg.Providers.GitDepth)
		o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
			Level: "info", Message: fmt.Sprintf("Cloning %s ...", o.target),
		}))
	} else {
		src = provider.NewLocalProvider()
	}

	result, err := src.Acquire(ctx, o.target)
	if err != nil {
		return o.fail(fmt.Errorf("provider: %w", err))
	}
	defer src.Cleanup()

	o.stageComplete(models.StageProvider)
	o.stageStart(models.StageResolvers)

	pc := &models.ProjectContext{}
	resolvers := []resolver.ContextResolver{
		resolver.NewFrameworkResolver(),
		resolver.NewPackageResolver(),
	}

	for _, r := range resolvers {
		if err := r.Resolve(ctx, result.RootPath, pc); err != nil {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "error", Message: fmt.Sprintf("Resolver %s failed: %v", r.Name(), err),
			}))
		}
	}
	o.bus.Publish(eventbus.NewEvent(eventbus.EventContextResolved, eventbus.ContextResolvedData{
		ProjectName:    pc.ProjectName,
		LaravelVersion: pc.LaravelVersion,
		PHPVersion:     pc.PHPVersion,
		FrameworkType:  pc.FrameworkType,
		PackageCount:   len(pc.InstalledPackages),
	}))
	if pc.FrameworkType == "" {
		o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
			Level: "warn", Message: "Framework not detected, applying baseline rules only",
		}))
	}

	rulesDir := o.getRulesDirectory()
	if rulesDir != "" {
		var allRules []config.RuleDefinition

		commonDir := filepath.Join(rulesDir, "common")
		if commonRules, err := config.LoadRulesFromDir(commonDir); err == nil {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "info", Message: fmt.Sprintf("Loading common security rules: %d rules", len(commonRules)),
			}))
			allRules = append(allRules, commonRules...)
		}

		frameworkKey := normalizeFrameworkRuleKey(pc.FrameworkType)
		if frameworkKey != "" {
			fwDir := filepath.Join(rulesDir, frameworkKey)
			if info, statErr := os.Stat(fwDir); statErr == nil && info.IsDir() {
				if fwRules, err := config.LoadRulesFromDir(fwDir); err == nil {
					o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
						Level: "info", Message: fmt.Sprintf("Loading framework specific rules (%s): %d rules", frameworkKey, len(fwRules)),
					}))
					allRules = append(allRules, fwRules...)
				}
			}
		}

		if rootRules, err := config.LoadRulesFromDir(rulesDir); err == nil {
			allRules = append(allRules, rootRules...)
		}

		if len(allRules) > 0 {
			deduped := deduplicateRuleDefinitions(allRules)
			frameworkAware := filterRulesByFramework(deduped, normalizeFrameworkRuleKey(pc.FrameworkType))
			filtered := o.filterRules(frameworkAware)
			if len(filtered) > 0 {
				scanners = append(scanners, depscanner.NewRulesScanner(filtered))
			}
		}
	}

	o.stageComplete(models.StageResolvers)
	o.stageStart(models.StageScanners)
	for _, sc := range scanners {
		o.bus.Publish(eventbus.NewEvent(eventbus.EventScannerRegistered, eventbus.ScannerRegisteredData{
			Name:        sc.Name(),
			Description: sc.Description(),
		}))
	}

	var allFindings []models.Finding
	scannersRun := make([]string, 0, len(scanners))
	scannerErrors := make(map[string]string)

	for _, sc := range scanners {
		if o.isScannerDisabled(sc.Name()) {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventScannerSkipped, eventbus.ScannerSkippedData{
				Name: sc.Name(), Reason: "disabled in config",
			}))
			continue
		}

		o.bus.Publish(eventbus.NewEvent(eventbus.EventScannerStarted, eventbus.ScannerStartedData{
			Name: sc.Name(),
		}))

		emit := func(f models.Finding) {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventFindingDiscovered, eventbus.FindingDiscoveredData{
				Finding: f,
			}))
		}

		findings, err := sc.Scan(ctx, *pc, emit)
		if err != nil {
			scannerErrors[sc.Name()] = err.Error()
			o.bus.Publish(eventbus.NewEvent(eventbus.EventScannerFailed, eventbus.ScannerFailedData{
				Name: sc.Name(), Error: err,
			}))
			continue
		}

		allFindings = append(allFindings, findings...)
		scannersRun = append(scannersRun, sc.Name())

		o.bus.Publish(eventbus.NewEvent(eventbus.EventScannerCompleted, eventbus.ScannerCompletedData{
			Name:         sc.Name(),
			FindingCount: len(findings),
		}))
	}

	o.stageComplete(models.StageScanners)
	o.stageStart(models.StagePostProcess)

	ip := NewIgnoreProcessor(o.target, &o.cfg.Ignore)
	filteredFindings := make([]models.Finding, 0, len(allFindings))
	for _, f := range allFindings {
		if ip.ShouldIgnore(f) {
			continue
		}
		filteredFindings = append(filteredFindings, f)
	}
	allFindings = filteredFindings

	allFindings = deduplicate(allFindings)
	allFindings = filterBySeverity(allFindings, models.ParseSeverity(o.cfg.Severity))

	o.stageComplete(models.StagePostProcess)
	o.stageStart(models.StageReport)

	endTime := time.Now()
	report := &models.ScanReport{
		ProjectContext: *pc,
		Findings:       allFindings,
		StartedAt:      startTime,
		CompletedAt:    endTime,
		Duration:       endTime.Sub(startTime),
		ScannersRun:    scannersRun,
		ScannerErrors:  scannerErrors,
	}

	reporters := o.buildReporters()
	for _, rep := range reporters {
		if err := rep.Generate(ctx, report); err != nil {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "error", Message: fmt.Sprintf("%s reporter failed: %v", rep.Name(), err),
			}))
		} else {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "info", Message: fmt.Sprintf("Report written to vanguard-report.%s", rep.Format()),
			}))
		}
	}
	diff, _ := store.CompareLast(report)
	if diff != nil {
		if len(diff.NewFindings) > 0 || len(diff.ResolvedFindings) > 0 {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "info", Message: fmt.Sprintf("vs last scan: %d new, %d resolved (%d→%d)",
					len(diff.NewFindings), len(diff.ResolvedFindings), diff.TotalBefore, diff.TotalAfter),
			}))
		}
	}

	if _, err := store.Save(report); err != nil {
		o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
			Level: "warn", Message: fmt.Sprintf("Failed to save scan history: %v", err),
		}))
	}

	o.stageComplete(models.StageReport)
	o.bus.Publish(eventbus.NewEvent(eventbus.EventScanCompleted, eventbus.ScanCompletedData{
		Report: report,
	}))

	return nil
}

func (o *Orchestrator) stageStart(stage models.PipelineStage) {
	o.bus.Publish(eventbus.NewEvent(eventbus.EventStageStarted, eventbus.StageStartedData{Stage: stage}))
}

func (o *Orchestrator) stageComplete(stage models.PipelineStage) {
	o.bus.Publish(eventbus.NewEvent(eventbus.EventStageCompleted, eventbus.StageCompletedData{Stage: stage}))
}

func (o *Orchestrator) fail(err error) error {
	o.bus.Publish(eventbus.NewEvent(eventbus.EventScanFailed, eventbus.ScanFailedData{Error: err}))
	return err
}

func (o *Orchestrator) isScannerDisabled(name string) bool {
	for _, d := range o.cfg.Scanners.Disable {
		if d == name {
			return true
		}
	}
	return false
}

func (o *Orchestrator) filterRules(rules []config.RuleDefinition) []config.RuleDefinition {
	if len(o.cfg.Scanners.RuleEnable) == 0 && len(o.cfg.Scanners.RuleDisable) == 0 {
		return rules
	}
	var out []config.RuleDefinition
	enableMap := make(map[string]bool)
	disableMap := make(map[string]bool)
	for _, id := range o.cfg.Scanners.RuleEnable {
		enableMap[id] = true
	}
	for _, id := range o.cfg.Scanners.RuleDisable {
		disableMap[id] = true
	}
	for _, r := range rules {
		if disableMap[r.ID] {
			continue
		}
		if len(enableMap) > 0 {
			if !enableMap[r.ID] {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func filterBySeverity(findings []models.Finding, minSeverity models.Severity) []models.Finding {
	if minSeverity == models.SeverityInfo {
		return findings
	}
	result := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= minSeverity {
			result = append(result, f)
		}
	}
	return result
}

func (o *Orchestrator) buildReporters() []reporter.Reporter {
	outDir := o.cfg.Output.Dir
	formats := o.cfg.Output.Formats
	if len(formats) == 0 {
		formats = []string{"json"}
	}

	var reporters []reporter.Reporter
	seen := make(map[string]bool)

	for _, f := range formats {
		if seen[f] {
			continue
		}
		seen[f] = true

		switch f {
		case "json":
			reporters = append(reporters, reporter.NewJSONReporter(outDir))
		case "sarif":
			reporters = append(reporters, reporter.NewSARIFReporter(outDir, o.version))
		case "html":
			reporters = append(reporters, reporter.NewHTMLReporter(outDir, o.version))
		case "markdown", "md":
			reporters = append(reporters, reporter.NewMarkdownReporter(outDir, o.version))
		case "terminal":
			continue
		}
	}
	if !seen["json"] {
		reporters = append(reporters, reporter.NewJSONReporter(outDir))
	}

	return reporters
}

func deduplicate(findings []models.Finding) []models.Finding {
	seen := make(map[string]bool)
	result := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.ID + "|" + f.File + "|" + fmt.Sprintf("%d", f.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}
func (o *Orchestrator) filterScanners(scanners []models.Scanner) []models.Scanner {
	enable := o.cfg.Scanners.Enable
	disable := o.cfg.Scanners.Disable

	if len(enable) == 0 && len(disable) == 0 {
		return scanners
	}

	enableSet := make(map[string]bool, len(enable))
	for _, name := range enable {
		enableSet[strings.ToLower(name)] = true
	}

	disableSet := make(map[string]bool, len(disable))
	for _, name := range disable {
		disableSet[strings.ToLower(name)] = true
	}

	var filtered []models.Scanner
	for _, s := range scanners {
		name := strings.ToLower(s.Name())
		if len(enableSet) > 0 && !enableSet[name] {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "info", Message: fmt.Sprintf("Skipping %s (not in enable list)", s.Name()),
			}))
			continue
		}
		if disableSet[name] {
			o.bus.Publish(eventbus.NewEvent(eventbus.EventLogMessage, eventbus.LogMessageData{
				Level: "info", Message: fmt.Sprintf("Skipping %s (disabled)", s.Name()),
			}))
			continue
		}

		filtered = append(filtered, s)
	}

	return filtered
}

func normalizeFrameworkRuleKey(frameworkType string) string {
	switch frameworkType {
	case "", "php-generic":
		return ""
	case "codeigniter2", "codeigniter3":
		return "codeigniter"
	case "lumen":
		return "laravel"
	default:
		return frameworkType
	}
}

func deduplicateRuleDefinitions(rules []config.RuleDefinition) []config.RuleDefinition {
	if len(rules) == 0 {
		return rules
	}

	seen := make(map[string]bool, len(rules))
	unique := make([]config.RuleDefinition, 0, len(rules))
	for _, rule := range rules {
		key := strings.TrimSpace(rule.ID)
		if key == "" {
			key = strings.TrimSpace(rule.Title) + "|" + strings.TrimSpace(rule.Category)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, rule)
	}
	return unique
}

func filterRulesByFramework(rules []config.RuleDefinition, framework string) []config.RuleDefinition {
	if len(rules) == 0 {
		return rules
	}

	normalizedFramework := normalizeFrameworkRuleKey(strings.ToLower(strings.TrimSpace(framework)))
	filtered := make([]config.RuleDefinition, 0, len(rules))

	for _, rule := range rules {
		required := inferRuleFramework(rule)
		if required == "" {
			filtered = append(filtered, rule)
			continue
		}
		if frameworkMatches(normalizedFramework, required) {
			filtered = append(filtered, rule)
		}
	}

	return filtered
}

func frameworkMatches(current, required string) bool {
	if required == "" {
		return true
	}
	if current == "" {
		return false
	}
	if current == required {
		return true
	}

	// CodeIgniter family aliases
	if (current == "codeigniter" || current == "codeigniter4") &&
		(required == "codeigniter" || required == "codeigniter4") {
		return true
	}

	return false
}

func inferRuleFramework(rule config.RuleDefinition) string {
	ruleID := strings.ToUpper(strings.TrimSpace(rule.ID))
	switch {
	case strings.HasPrefix(ruleID, "LAR-"):
		return "laravel"
	case strings.HasPrefix(ruleID, "SYM-"):
		return "symfony"
	case strings.HasPrefix(ruleID, "WP-"):
		return "wordpress"
	case strings.HasPrefix(ruleID, "CI4-"):
		return "codeigniter4"
	case strings.HasPrefix(ruleID, "CI-"):
		return "codeigniter"
	case strings.HasPrefix(ruleID, "YII-"):
		return "yii2"
	case strings.HasPrefix(ruleID, "CAKE-"):
		return "cakephp"
	}

	for _, p := range rule.Patterns {
		target := strings.ToLower(strings.TrimSpace(p.Target))
		switch target {
		case "blade-files":
			return "laravel"
		case "twig-files":
			return "symfony"
		}
	}

	tagBlob := strings.ToLower(strings.Join(rule.Tags, " "))
	switch {
	case containsAny(tagBlob, "laravel", "lumen", "blade", "eloquent", "artisan", "sanctum", "passport", "telescope", "horizon", "reverb"):
		return "laravel"
	case containsAny(tagBlob, "symfony", "twig", "doctrine"):
		return "symfony"
	case containsAny(tagBlob, "wordpress", " wp_", "wp-", "wpsec"):
		return "wordpress"
	case containsAny(tagBlob, "codeigniter4", "ci4"):
		return "codeigniter4"
	case containsAny(tagBlob, "codeigniter", "ci3", "ci2"):
		return "codeigniter"
	case containsAny(tagBlob, "yii2", " yii "):
		return "yii2"
	case containsAny(tagBlob, "cakephp"):
		return "cakephp"
	}

	textBlob := strings.ToLower(rule.Title + " " + rule.Description + " " + rule.Remediation)
	switch {
	case containsAny(textBlob, "laravel", "blade", "eloquent", "artisan", "sanctum", "passport"):
		return "laravel"
	case containsAny(textBlob, "symfony", "twig"):
		return "symfony"
	case containsAny(textBlob, "wordpress", "wp_"):
		return "wordpress"
	case containsAny(textBlob, "codeigniter"):
		return "codeigniter"
	case containsAny(textBlob, "yii2", "yii framework"):
		return "yii2"
	case containsAny(textBlob, "cakephp"):
		return "cakephp"
	}

	return ""
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func (o *Orchestrator) getRulesDirectory() string {

	candidates := []string{
		filepath.Join(o.target, "rules"),
		filepath.Join(o.target, "vanguard-rules"),
		filepath.Join(o.target, ".vanguard-rules"),
	}

	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "rules"),
			filepath.Join(exeDir, "vanguard-rules"),
		)
	}

	cwd, err := os.Getwd()
	if err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "rules"),
			filepath.Join(cwd, "vanguard-rules"),
		)
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate
		}
	}

	return ""
}
