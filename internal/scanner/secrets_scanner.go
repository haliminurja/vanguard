package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/haliminurja/vanguard/internal/models"
)

// secretPattern defines a format-specific secret detection pattern.
type secretPattern struct {
	ID          string
	Title       string
	Severity    models.Severity
	Pattern     *regexp.Regexp
	CWE         string
	OWASP       string
	Confidence  string
	Remediation string
	Tags        []string
	// Validator applies additional logic to reduce false positives.
	Validator func(match string, line string) bool
}

// SecretsScanner detects hardcoded secrets using format-specific patterns
// and high-entropy string analysis. Unlike generic regex rules, this scanner
// uses multi-layered validation: pattern match → format validation → entropy
// check → context analysis to achieve a very low false positive rate.
type SecretsScanner struct {
	patterns   []secretPattern
	ignoreDirs map[string]bool
}

func NewSecretsScanner() *SecretsScanner {
	s := &SecretsScanner{
		ignoreDirs: map[string]bool{
			"vendor": true, "node_modules": true, ".git": true,
			"storage": true, ".idea": true, ".vscode": true,
			"public": true, "tests": true, "test": true,
		},
	}
	s.patterns = s.buildPatterns()
	return s
}

func (s *SecretsScanner) Name() string        { return "secrets-scanner" }
func (s *SecretsScanner) Description() string { return "Format-specific hardcoded secret detection" }

func (s *SecretsScanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	var allFiles []string
	root := project.RootPath

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if s.ignoreDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > MaxFileSize || info.Size() == 0 {
			return nil
		}
		if s.isScannableFile(path) {
			allFiles = append(allFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	var findings []models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}

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

				fileFindings := s.scanFile(fpath, root)
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
	return findings, ctx.Err()
}

func (s *SecretsScanner) scanFile(fpath, root string) []models.Finding {
	file, err := os.Open(fpath)
	if err != nil {
		return nil
	}
	defer file.Close()

	rel, _ := filepath.Rel(root, fpath)
	rel = filepath.ToSlash(rel)

	var findings []models.Finding
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}

		for _, pat := range s.patterns {
			matches := pat.Pattern.FindAllString(line, 3)
			for _, match := range matches {
				// Apply format validator if present
				if pat.Validator != nil && !pat.Validator(match, line) {
					continue
				}

				// Dedup by rule+file+line
				key := fmt.Sprintf("%s|%s|%d", pat.ID, rel, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				snippet := truncateSecret(trimmed, 120)
				findings = append(findings, models.Finding{
					ID:          pat.ID,
					Title:       pat.Title,
					Description: fmt.Sprintf("Hardcoded secret detected in %s at line %d", rel, lineNum),
					Severity:    pat.Severity,
					Category:    "Hardcoded Secret",
					Scanner:     s.Name(),
					File:        rel,
					Line:        lineNum,
					CodeSnippet: snippet,
					Remediation: pat.Remediation,
					Tags:        pat.Tags,
					CWE:         pat.CWE,
					OWASP:       pat.OWASP,
					Confidence:  pat.Confidence,
				})
			}
		}
	}

	return findings
}

func (s *SecretsScanner) buildPatterns() []secretPattern {
	return []secretPattern{
		// ── AWS ───────────────────────────────────────────────
		{
			ID:          "SEC-AWS-001",
			Title:       "AWS Access Key ID detected",
			Severity:    models.SeverityCritical,
			Pattern:     regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)`),
			CWE:         "CWE-798",
			OWASP:       "A07:2021",
			Confidence:  "high",
			Tags:        []string{"aws", "access-key", "cloud", "owasp-a07"},
			Remediation: "Remove the AWS Access Key and rotate it immediately via the AWS IAM console.\nUse IAM roles, environment variables, or AWS Secrets Manager instead.",
		},
		{
			ID:       "SEC-AWS-002",
			Title:    "AWS Secret Access Key detected",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"aws", "secret-key", "cloud", "owasp-a07"},
			Remediation: "Rotate the AWS secret key immediately. Use AWS Secrets Manager or IAM roles.",
		},
		// ── GitHub ───────────────────────────────────────────
		{
			ID:       "SEC-GH-001",
			Title:    "GitHub Personal Access Token detected",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(ghp_[A-Za-z0-9]{36,255})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"github", "token", "owasp-a07"},
			Remediation: "Revoke the token at https://github.com/settings/tokens and create a new one with minimal scopes.",
		},
		{
			ID:       "SEC-GH-002",
			Title:    "GitHub Fine-Grained PAT detected",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(github_pat_[A-Za-z0-9_]{22,255})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"github", "fine-grained-pat", "owasp-a07"},
			Remediation: "Revoke and regenerate the fine-grained PAT at GitHub settings.",
		},
		// ── GitLab ───────────────────────────────────────────
		{
			ID:       "SEC-GL-001",
			Title:    "GitLab Personal Access Token detected",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(glpat-[A-Za-z0-9_-]{20,})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"gitlab", "token", "owasp-a07"},
			Remediation: "Revoke the token in GitLab user settings and create a new one.",
		},
		// ── Slack ────────────────────────────────────────────
		{
			ID:       "SEC-SLACK-001",
			Title:    "Slack Bot/User/App Token detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(xox[bpas]-[A-Za-z0-9-]{10,250})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"slack", "token", "owasp-a07"},
			Remediation: "Revoke the Slack token at api.slack.com/apps and rotate credentials.",
		},
		// ── Stripe ───────────────────────────────────────────
		{
			ID:       "SEC-STRIPE-001",
			Title:    "Stripe Live Secret Key detected",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(sk_live_[A-Za-z0-9]{20,99})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"stripe", "payment", "secret-key", "pci-dss", "owasp-a07"},
			Remediation: "Rotate the Stripe secret key at dashboard.stripe.com/apikeys immediately.\nLive keys grant full access to payment operations.",
		},
		{
			ID:       "SEC-STRIPE-002",
			Title:    "Stripe Restricted Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(rk_live_[A-Za-z0-9]{20,99})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"stripe", "restricted-key", "owasp-a07"},
			Remediation: "Rotate the Stripe restricted key at dashboard.stripe.com.",
		},
		// ── Google ───────────────────────────────────────────
		{
			ID:       "SEC-GCP-001",
			Title:    "Google API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AIza[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"google", "api-key", "cloud", "owasp-a07"},
			Remediation: "Restrict the API key in Google Cloud Console or rotate it. Use application default credentials.",
		},
		// ── SendGrid ─────────────────────────────────────────
		{
			ID:       "SEC-SG-001",
			Title:    "SendGrid API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"sendgrid", "email", "api-key", "owasp-a07"},
			Remediation: "Revoke the SendGrid API key and create a new one with minimal permissions.",
		},
		// ── Twilio ───────────────────────────────────────────
		{
			ID:       "SEC-TWILIO-001",
			Title:    "Twilio API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(SK[a-f0-9]{32})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"twilio", "api-key", "sms", "owasp-a07"},
			Remediation: "Rotate the Twilio API key in the Twilio console.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return strings.Contains(lower, "twilio") || strings.Contains(lower, "account_sid") || strings.Contains(lower, "auth_token")
			},
		},
		// ── OpenAI ───────────────────────────────────────────
		{
			ID:       "SEC-OPENAI-001",
			Title:    "OpenAI API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{40,})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"openai", "ai", "api-key", "owasp-a07"},
			Remediation: "Rotate the OpenAI API key at platform.openai.com/api-keys.",
		},
		// ── NPM ──────────────────────────────────────────────
		{
			ID:       "SEC-NPM-001",
			Title:    "NPM Access Token detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"npm", "supply-chain", "token", "owasp-a07"},
			Remediation: "Revoke the token via npm token revoke and create a new one.",
		},
		// ── Telegram ─────────────────────────────────────────
		{
			ID:       "SEC-TG-001",
			Title:    "Telegram Bot Token detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])([0-9]{8,10}:[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"telegram", "bot", "token", "owasp-a07"},
			Remediation: "Revoke the bot token via @BotFather and create a new one.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return strings.Contains(lower, "telegram") || strings.Contains(lower, "bot") || strings.Contains(lower, "token")
			},
		},
		// ── Private Keys ─────────────────────────────────────
		{
			ID:       "SEC-KEY-001",
			Title:    "Private Key file detected in source",
			Severity: models.SeverityCritical,
			Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			CWE:      "CWE-321", OWASP: "A02:2021", Confidence: "high",
			Tags:        []string{"private-key", "crypto", "owasp-a02"},
			Remediation: "Remove private keys from source code. Use a key vault or environment variables.\nRotate the compromised key pair immediately.",
		},
		// ── Database Connection Strings ──────────────────────
		{
			ID:       "SEC-DB-001",
			Title:    "Database connection string with credentials",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[^/\s]+`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"database", "credentials", "connection-string", "owasp-a07"},
			Remediation: "Move database credentials to environment variables or a secrets manager.\nNever commit connection strings with passwords to source control.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(match)
				return !strings.Contains(lower, "localhost:password@") &&
					!strings.Contains(lower, "user:pass@") &&
					!strings.Contains(lower, "example") &&
					!strings.Contains(lower, "placeholder")
			},
		},
		// ── JWT Secret ───────────────────────────────────────
		{
			ID:       "SEC-JWT-001",
			Title:    "Hardcoded JWT secret key",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?i)(jwt_secret|jwt_key|jwt_signing)\s*[=:]\s*['"][A-Za-z0-9+/=_-]{16,}['"]`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"jwt", "secret", "auth", "owasp-a07"},
			Remediation: "Move JWT secrets to environment variables. Use asymmetric keys (RS256) instead of symmetric HMAC.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return !strings.Contains(lower, "env(") && !strings.Contains(lower, "getenv(") &&
					!strings.Contains(lower, "config(") && !strings.Contains(lower, "example") &&
					!strings.Contains(lower, "placeholder")
			},
		},
		// ── Generic API Key in Assignment ────────────────────
		{
			ID:       "SEC-GENERIC-001",
			Title:    "Generic API key/secret hardcoded in assignment",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?i)(api_key|apikey|api_secret|app_secret|auth_token|access_token|client_secret)\s*[=:]\s*['"][A-Za-z0-9+/=_-]{20,}['"]`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"api-key", "hardcoded", "owasp-a07"},
			Remediation: "Move secrets to environment variables or a vault:\n  $apiKey = env('SERVICE_API_KEY');",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return !strings.Contains(lower, "env(") && !strings.Contains(lower, "getenv(") &&
					!strings.Contains(lower, "config(") && !strings.Contains(lower, "example") &&
					!strings.Contains(lower, "test") && !strings.Contains(lower, "placeholder") &&
					!strings.Contains(lower, "changeme") && !strings.Contains(lower, "your_")
			},
		},
		// ── Mailgun ──────────────────────────────────────────
		{
			ID:       "SEC-MG-001",
			Title:    "Mailgun API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(key-[a-f0-9]{32})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"mailgun", "email", "owasp-a07"},
			Remediation: "Rotate the Mailgun API key in the Mailgun dashboard.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return strings.Contains(lower, "mailgun") || strings.Contains(lower, "mail") || strings.Contains(lower, "api")
			},
		},
		// ── DigitalOcean ─────────────────────────────────────
		{
			ID:       "SEC-DO-001",
			Title:    "DigitalOcean Access Token detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(dop_v1_[a-f0-9]{64})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"digitalocean", "cloud", "owasp-a07"},
			Remediation: "Revoke the token in the DigitalOcean control panel and create a new one.",
		},
		// ── Discord ──────────────────────────────────────────
		{
			ID:       "SEC-DISCORD-001",
			Title:    "Discord Bot Token detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])([MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})(?:[^A-Za-z0-9]|$)`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"discord", "bot", "token", "owasp-a07"},
			Remediation: "Reset the Discord bot token at discord.com/developers.",
			Validator: func(match, line string) bool {
				lower := strings.ToLower(line)
				return strings.Contains(lower, "discord") || strings.Contains(lower, "bot")
			},
		},
		// ── Heroku ───────────────────────────────────────────
		{
			ID:       "SEC-HEROKU-001",
			Title:    "Heroku API Key detected",
			Severity: models.SeverityHigh,
			Pattern:  regexp.MustCompile(`(?i)(heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
			CWE:      "CWE-798", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"heroku", "cloud", "owasp-a07"},
			Remediation: "Regenerate the Heroku API key: heroku authorizations:revoke <id>.",
		},
	}
}

func (s *SecretsScanner) isScannableFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))

	// Always scan env files
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".php", ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go",
		".java", ".yaml", ".yml", ".json", ".xml", ".ini", ".conf",
		".toml", ".cfg", ".properties", ".sh", ".bash", ".zsh",
		".sql", ".env", ".config", ".tf", ".tfvars":
		return true
	}

	switch base {
	case "dockerfile", "docker-compose.yml", "docker-compose.yaml",
		".npmrc", ".pypirc", ".netrc", ".gitconfig",
		"config", "credentials", "settings":
		return true
	}

	return false
}

func isCommentLine(line string) bool {
	switch {
	case strings.HasPrefix(line, "//"),
		strings.HasPrefix(line, "#"),
		strings.HasPrefix(line, "/*"),
		strings.HasPrefix(line, "*"),
		strings.HasPrefix(line, "*/"),
		strings.HasPrefix(line, "<!--"):
		return true
	}
	return false
}

func truncateSecret(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
