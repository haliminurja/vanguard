package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/haliminurja/vanguard/internal/models"
)

// configCheck defines a configuration security audit check.
type configCheck struct {
	ID          string
	Title       string
	Description string
	Severity    models.Severity
	Category    string
	CWE         string
	OWASP       string
	Confidence  string
	Remediation string
	Tags        []string
	// Check returns findings for the given project root.
	Check func(root string) []configFinding
}

type configFinding struct {
	File    string
	Line    int
	Snippet string
}

// ConfigScanner audits PHP runtime configuration, web server settings,
// and security header configuration for production-readiness.
type ConfigScanner struct {
	checks []configCheck
}

func NewConfigScanner() *ConfigScanner {
	s := &ConfigScanner{}
	s.checks = s.buildChecks()
	return s
}

func (s *ConfigScanner) Name() string        { return "config-scanner" }
func (s *ConfigScanner) Description() string { return "PHP & server configuration security auditor" }

func (s *ConfigScanner) Scan(ctx context.Context, project models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	root := project.RootPath
	var findings []models.Finding

	for _, check := range s.checks {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		results := check.Check(root)
		for _, r := range results {
			f := models.Finding{
				ID:          check.ID,
				Title:       check.Title,
				Description: check.Description,
				Severity:    check.Severity,
				Category:    check.Category,
				Scanner:     s.Name(),
				File:        r.File,
				Line:        r.Line,
				CodeSnippet: r.Snippet,
				Remediation: check.Remediation,
				Tags:        check.Tags,
				CWE:         check.CWE,
				OWASP:       check.OWASP,
				Confidence:  check.Confidence,
			}
			findings = append(findings, f)
			emit(f)
		}
	}

	return findings, nil
}

func (s *ConfigScanner) buildChecks() []configCheck {
	return []configCheck{
		// ── PHP Configuration (.env / config files) ─────────
		{
			ID:          "CFG-ENV-001",
			Title:       "APP_DEBUG=true in production environment",
			Description: "APP_DEBUG is set to true. In production, this exposes stack traces, environment variables, database credentials, and internal paths to attackers via error pages.",
			Severity:    models.SeverityCritical,
			Category:    "Security Misconfiguration",
			CWE:         "CWE-215", OWASP: "A05:2021", Confidence: "high",
			Tags:        []string{"debug", "env", "owasp-a05", "production"},
			Remediation: "Set APP_DEBUG=false in production .env files.\nUse structured logging instead of debug output.",
			Check:       checkEnvDebug,
		},
		{
			ID:          "CFG-ENV-002",
			Title:       "APP_ENV set to local/development in deployment",
			Description: "APP_ENV is not set to 'production'. Non-production environments may have relaxed security settings, verbose error handling, and exposed debug tools.",
			Severity:    models.SeverityHigh,
			Category:    "Security Misconfiguration",
			CWE:         "CWE-16", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"env", "environment", "owasp-a05"},
			Remediation: "Set APP_ENV=production in deployment environments.",
			Check:       checkEnvEnvironment,
		},
		{
			ID:          "CFG-ENV-003",
			Title:       "Database credentials with weak or default password",
			Description: "Database password in .env is empty, 'password', 'root', 'secret', or another common default. Automated scanners try these defaults first.",
			Severity:    models.SeverityHigh,
			Category:    "Weak Credentials",
			CWE:         "CWE-521", OWASP: "A07:2021", Confidence: "high",
			Tags:        []string{"database", "credentials", "default-password", "owasp-a07"},
			Remediation: "Use a strong, unique database password (24+ random characters).\nGenerate with: openssl rand -base64 32",
			Check:       checkWeakDBPassword,
		},
		{
			ID:          "CFG-ENV-004",
			Title:       "Mail credentials hardcoded in .env",
			Description: "SMTP credentials (MAIL_PASSWORD) are present in .env with what appears to be a real password. If .env is committed to version control, credentials are exposed.",
			Severity:    models.SeverityMedium,
			Category:    "Hardcoded Credentials",
			CWE:         "CWE-798", OWASP: "A07:2021", Confidence: "medium",
			Tags:        []string{"mail", "smtp", "credentials", "owasp-a07"},
			Remediation: "Use a secrets manager or encrypted environment variables for mail credentials.",
			Check:       checkMailCredentials,
		},
		// ── .htaccess Security ──────────────────────────────
		{
			ID:          "CFG-HTA-001",
			Title:       ".htaccess missing — directory listing may be exposed",
			Description: "No .htaccess file found in the public directory. Without proper configuration, Apache may allow directory listing, exposing file structure and sensitive files.",
			Severity:    models.SeverityMedium,
			Category:    "Security Misconfiguration",
			CWE:         "CWE-548", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"apache", "htaccess", "directory-listing", "owasp-a05"},
			Remediation: "Create a .htaccess file in the public directory:\n  Options -Indexes\n  <FilesMatch \"\\.(env|log|sql)$\">\n    Require all denied\n  </FilesMatch>",
			Check:       checkHtaccessExists,
		},
		{
			ID:          "CFG-HTA-002",
			Title:       ".htaccess allows access to sensitive file types",
			Description: ".htaccess does not block access to .env, .log, .sql, .bak, and other sensitive file extensions. These files can be downloaded directly via HTTP.",
			Severity:    models.SeverityHigh,
			Category:    "Information Disclosure",
			CWE:         "CWE-538", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"apache", "htaccess", "file-protection", "owasp-a05"},
			Remediation: "Add file protection rules to .htaccess:\n  <FilesMatch \"\\.(env|log|sql|bak|config|dist|ini|sh|swp)$\">\n    Require all denied\n  </FilesMatch>",
			Check:       checkHtaccessFileProt,
		},
		// ── PHP Configuration Detection ─────────────────────
		{
			ID:          "CFG-PHP-001",
			Title:       "display_errors enabled in PHP configuration",
			Description: "display_errors is set to On or 1 in php.ini, .user.ini, or .htaccess. PHP error messages reveal file paths, database queries, and code structure to attackers.",
			Severity:    models.SeverityHigh,
			Category:    "Information Disclosure",
			CWE:         "CWE-209", OWASP: "A05:2021", Confidence: "high",
			Tags:        []string{"php", "display-errors", "owasp-a05"},
			Remediation: "Set display_errors = Off in php.ini and .user.ini.\nUse log_errors = On with error_log for production error tracking.",
			Check:       checkPHPDisplayErrors,
		},
		{
			ID:          "CFG-PHP-002",
			Title:       "expose_php enabled — server reveals PHP version",
			Description: "expose_php is On in php.ini, causing the X-Powered-By: PHP/x.x.x header to be sent. This reveals the exact PHP version to attackers, enabling version-specific exploits.",
			Severity:    models.SeverityLow,
			Category:    "Information Disclosure",
			CWE:         "CWE-200", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"php", "version-disclosure", "owasp-a05"},
			Remediation: "Set expose_php = Off in php.ini.",
			Check:       checkPHPExposePhp,
		},
		{
			ID:          "CFG-PHP-003",
			Title:       "allow_url_include enabled — remote code execution risk",
			Description: "allow_url_include is set to On, allowing include/require to load PHP files from remote URLs. This is a direct remote code execution vector.",
			Severity:    models.SeverityCritical,
			Category:    "Remote Code Execution",
			CWE:         "CWE-98", OWASP: "A03:2021", Confidence: "high",
			Tags:        []string{"php", "rfi", "rce", "owasp-a03"},
			Remediation: "Set allow_url_include = Off in php.ini. This should always be disabled.",
			Check:       checkPHPAllowUrlInclude,
		},
		// ── Security Headers ─────────────────────────────────
		{
			ID:          "CFG-HDR-001",
			Title:       "Missing Content-Security-Policy (CSP) header configuration",
			Description: "No CSP header configuration found in web server or application config. CSP is the primary defense against XSS, preventing inline scripts and unauthorized resource loading.",
			Severity:    models.SeverityMedium,
			Category:    "Missing Security Headers",
			CWE:         "CWE-693", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"csp", "headers", "xss-prevention", "owasp-a05"},
			Remediation: "Configure Content-Security-Policy header:\n  default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
			Check:       checkCSPHeader,
		},
		{
			ID:          "CFG-HDR-002",
			Title:       "Missing Strict-Transport-Security (HSTS) configuration",
			Description: "No HSTS header configuration found. Without HSTS, the first request may use HTTP, enabling man-in-the-middle attacks and SSL stripping.",
			Severity:    models.SeverityMedium,
			Category:    "Missing Security Headers",
			CWE:         "CWE-319", OWASP: "A02:2021", Confidence: "medium",
			Tags:        []string{"hsts", "https", "headers", "owasp-a02"},
			Remediation: "Configure Strict-Transport-Security header:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			Check:       checkHSTSHeader,
		},
		{
			ID:          "CFG-HDR-003",
			Title:       "Missing X-Frame-Options or frame-ancestors CSP",
			Description: "No clickjacking protection found. Without X-Frame-Options or frame-ancestors CSP, the application can be embedded in iframes for clickjacking attacks.",
			Severity:    models.SeverityMedium,
			Category:    "Missing Security Headers",
			CWE:         "CWE-1021", OWASP: "A05:2021", Confidence: "medium",
			Tags:        []string{"clickjacking", "x-frame-options", "headers", "owasp-a05"},
			Remediation: "Add X-Frame-Options header or CSP frame-ancestors:\n  X-Frame-Options: DENY\n  Or: Content-Security-Policy: frame-ancestors 'none';",
			Check:       checkXFrameOptions,
		},
		// ── .env in version control ──────────────────────────
		{
			ID:          "CFG-GIT-001",
			Title:       ".env file not in .gitignore",
			Description: ".env file exists but is not listed in .gitignore. Environment files contain database passwords, API keys, and encryption keys. Committing them to version control exposes all secrets in the repository history permanently.",
			Severity:    models.SeverityCritical,
			Category:    "Secrets Management",
			CWE:         "CWE-312", OWASP: "A05:2021", Confidence: "high",
			Tags:        []string{"git", "env", "secrets", "owasp-a05"},
			Remediation: "Add .env to .gitignore:\n  echo '.env' >> .gitignore\n  git rm --cached .env\nIf already committed, rotate ALL secrets in the .env file.",
			Check:       checkEnvInGitignore,
		},
	}
}

// ── Check Implementations ────────────────────────────────────

func checkEnvDebug(root string) []configFinding {
	return scanEnvForPattern(root, regexp.MustCompile(`(?i)^APP_DEBUG\s*=\s*(true|1)\s*$`))
}

func checkEnvEnvironment(root string) []configFinding {
	return scanEnvForPattern(root, regexp.MustCompile(`(?i)^APP_ENV\s*=\s*(local|development|dev|staging|testing)\s*$`))
}

func checkWeakDBPassword(root string) []configFinding {
	weakPasswords := regexp.MustCompile(`(?i)^DB_PASSWORD\s*=\s*(|password|root|secret|admin|123456|test|mysql|postgres|changeme|qwerty|letmein|pass|default)\s*$`)
	return scanEnvForPattern(root, weakPasswords)
}

func checkMailCredentials(root string) []configFinding {
	return scanEnvForPattern(root, regexp.MustCompile(`(?i)^MAIL_PASSWORD\s*=\s*\S{4,}\s*$`))
}

func checkHtaccessExists(root string) []configFinding {
	publicDirs := []string{"public", "public_html", "www", "web", "httpdocs"}
	for _, dir := range publicDirs {
		publicPath := filepath.Join(root, dir)
		if info, err := os.Stat(publicPath); err == nil && info.IsDir() {
			htPath := filepath.Join(publicPath, ".htaccess")
			if _, err := os.Stat(htPath); os.IsNotExist(err) {
				return []configFinding{{File: filepath.ToSlash(dir), Snippet: "[.htaccess NOT FOUND]"}}
			}
			return nil
		}
	}
	return nil
}

func checkHtaccessFileProt(root string) []configFinding {
	htPaths := []string{
		filepath.Join(root, "public", ".htaccess"),
		filepath.Join(root, "public_html", ".htaccess"),
		filepath.Join(root, ".htaccess"),
	}
	for _, htPath := range htPaths {
		data, err := os.ReadFile(htPath)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		if !strings.Contains(content, ".env") && !strings.Contains(content, "filesmatch") {
			rel, _ := filepath.Rel(root, htPath)
			return []configFinding{{File: filepath.ToSlash(rel), Snippet: "[SENSITIVE FILE TYPES NOT BLOCKED]"}}
		}
		return nil
	}
	return nil
}

func checkPHPDisplayErrors(root string) []configFinding {
	return scanPHPIniForPattern(root, regexp.MustCompile(`(?i)^\s*display_errors\s*=\s*(on|1|true|yes)\s*$`))
}

func checkPHPExposePhp(root string) []configFinding {
	return scanPHPIniForPattern(root, regexp.MustCompile(`(?i)^\s*expose_php\s*=\s*(on|1|true|yes)\s*$`))
}

func checkPHPAllowUrlInclude(root string) []configFinding {
	return scanPHPIniForPattern(root, regexp.MustCompile(`(?i)^\s*allow_url_include\s*=\s*(on|1|true|yes)\s*$`))
}

func checkCSPHeader(root string) []configFinding {
	return checkSecurityHeaderPresence(root, "content-security-policy", "Content-Security-Policy")
}

func checkHSTSHeader(root string) []configFinding {
	return checkSecurityHeaderPresence(root, "strict-transport-security", "Strict-Transport-Security")
}

func checkXFrameOptions(root string) []configFinding {
	return checkSecurityHeaderPresence(root, "x-frame-options", "X-Frame-Options")
}

func checkEnvInGitignore(root string) []configFinding {
	envPath := filepath.Join(root, ".env")
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		return nil
	}

	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		return []configFinding{{File: ".env", Snippet: "[.gitignore NOT FOUND — .env may be committed]"}}
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == ".env" || trimmed == ".env*" || trimmed == "*.env" {
			return nil
		}
	}
	return []configFinding{{File: ".env", Snippet: "[.env NOT IN .gitignore]"}}
}

// ── Helper Functions ─────────────────────────────────────────

func scanEnvForPattern(root string, pattern *regexp.Regexp) []configFinding {
	envFiles := []string{".env", ".env.production", ".env.staging"}
	var results []configFinding

	for _, envFile := range envFiles {
		envPath := filepath.Join(root, envFile)
		findings := scanFileForPattern(envPath, root, pattern)
		results = append(results, findings...)
	}
	return results
}

func scanPHPIniForPattern(root string, pattern *regexp.Regexp) []configFinding {
	candidates := []string{
		"php.ini", ".user.ini",
		filepath.Join("public", ".user.ini"),
		filepath.Join("public", "php.ini"),
		filepath.Join("public_html", ".user.ini"),
	}

	var results []configFinding
	for _, candidate := range candidates {
		fullPath := filepath.Join(root, candidate)
		findings := scanFileForPattern(fullPath, root, pattern)
		results = append(results, findings...)
	}

	// Also check .htaccess for php_value/php_flag directives
	htPaths := []string{".htaccess", filepath.Join("public", ".htaccess")}
	for _, htFile := range htPaths {
		fullPath := filepath.Join(root, htFile)
		findings := scanFileForPattern(fullPath, root, pattern)
		results = append(results, findings...)
	}

	return results
}

func scanFileForPattern(filePath, root string, pattern *regexp.Regexp) []configFinding {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	rel, _ := filepath.Rel(root, filePath)
	rel = filepath.ToSlash(rel)

	var results []configFinding
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if pattern.MatchString(line) {
			results = append(results, configFinding{
				File:    rel,
				Line:    lineNum,
				Snippet: strings.TrimSpace(line),
			})
		}
	}
	return results
}

func checkSecurityHeaderPresence(root, headerLower, headerDisplay string) []configFinding {
	// Search for header configuration in common locations
	searchFiles := []string{
		filepath.Join(root, "public", ".htaccess"),
		filepath.Join(root, ".htaccess"),
	}

	// Check nginx configs
	nginxCandidates := []string{
		filepath.Join(root, "nginx.conf"),
		filepath.Join(root, "docker", "nginx", "default.conf"),
		filepath.Join(root, "docker", "nginx.conf"),
	}
	searchFiles = append(searchFiles, nginxCandidates...)

	// Check PHP middleware/config that sets headers
	phpHeaderFiles := []string{
		filepath.Join(root, "app", "Http", "Middleware", "SecurityHeaders.php"),
		filepath.Join(root, "app", "Http", "Middleware", "SecureHeaders.php"),
		filepath.Join(root, "config", "secure-headers.php"),
		filepath.Join(root, "config", "headers.php"),
	}
	searchFiles = append(searchFiles, phpHeaderFiles...)

	for _, filePath := range searchFiles {
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		if strings.Contains(content, headerLower) {
			return nil // Header is configured somewhere
		}
	}

	// Check if any PHP file in the middleware directory sets this header
	middlewareDir := filepath.Join(root, "app", "Http", "Middleware")
	if entries, err := os.ReadDir(middlewareDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".php") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(middlewareDir, entry.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(strings.ToLower(string(data)), headerLower) {
				return nil
			}
		}
	}

	return []configFinding{{
		File:    "project",
		Snippet: fmt.Sprintf("[%s HEADER NOT CONFIGURED]", headerDisplay),
	}}
}
