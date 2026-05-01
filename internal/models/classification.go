package models

import "strings"

type FindingClassification struct {
	VulnerabilityClass string
	AttackSurface      string
	Impact             string
	Compliance         []string
}

func (f Finding) Classification() FindingClassification {
	blob := strings.ToLower(strings.Join([]string{
		f.ID,
		f.Title,
		f.Description,
		f.Category,
		f.Scanner,
		f.File,
		f.Remediation,
		f.CWE,
		f.OWASP,
		strings.Join(f.Tags, " "),
	}, " "))

	return FindingClassification{
		VulnerabilityClass: classifyVulnerability(blob, f),
		AttackSurface:      classifyAttackSurface(blob, f),
		Impact:             classifyImpact(blob, f),
		Compliance:         classifyCompliance(f),
	}
}

func classifyVulnerability(blob string, f Finding) string {
	switch {
	case f.Scanner == "dependency-scanner" || hasAny(blob, "dependency", "supply-chain", "composer", "npm", "yarn", "pnpm"):
		return "dependency-management"
	case hasAny(blob, "secret", "credential", "private key", "api key", "token leakage", "password"):
		return "secrets-management"
	case hasAny(blob, "rce", "code injection", "command injection", "eval", "exec", "system(", "cwe-78", "cwe-94", "cwe-95"):
		return "code-execution"
	case hasAny(blob, "sql injection", "sqli", "cwe-89"):
		return "sql-injection"
	case hasAny(blob, "xss", "cross-site scripting", "cwe-79"):
		return "cross-site-scripting"
	case hasAny(blob, "ssrf", "server-side request forgery", "cwe-918"):
		return "ssrf"
	case hasAny(blob, "deserialization", "unserialize", "object injection", "cwe-502"):
		return "deserialization"
	case hasAny(blob, "file upload", "unrestricted upload", "cwe-434"):
		return "file-upload"
	case hasAny(blob, "path traversal", "directory traversal", "zip slip", "lfi", "rfi", "cwe-22"):
		return "path-traversal"
	case hasAny(blob, "idor", "authorization", "access control", "privilege", "cwe-639", "cwe-862", "cwe-863"):
		return "authorization"
	case hasAny(blob, "authentication", "auth bypass", "cwe-287", "cwe-306"):
		return "authentication"
	case hasAny(blob, "csrf", "cwe-352"):
		return "csrf"
	case hasAny(blob, "cryptographic", "crypto", "cipher", "hashing", "cwe-327", "cwe-328", "cwe-321"):
		return "cryptography"
	case hasAny(blob, "session", "cookie", "cwe-613", "cwe-614"):
		return "session-management"
	case hasAny(blob, "cors", "security misconfiguration", "debug", "information disclosure", "cwe-200", "cwe-209", "cwe-16"):
		return "security-configuration"
	case hasAny(blob, "logging", "monitoring", "audit trail"):
		return "logging-monitoring"
	case hasAny(blob, "business logic", "workflow", "rate limit", "race condition"):
		return "business-logic"
	case hasAny(blob, "api", "graphql", "webhook", "rest"):
		return "api-security"
	case hasAny(blob, "php compatibility", "deprecated", "removed function"):
		return "runtime-compatibility"
	default:
		return normalizeClassificationValue(f.Category, "unclassified")
	}
}

func classifyAttackSurface(blob string, f Finding) string {
	switch {
	case f.Scanner == "dependency-scanner" || hasAny(blob, "dependency", "supply-chain", "composer", "npm", "yarn", "pnpm", "install script"):
		return "supply-chain"
	case hasAny(blob, "env", "config", "configuration", "cors", "phpunit", ".htaccess"):
		return "configuration"
	case hasAny(blob, "api", "graphql", "webhook", "rest", "ajax", "jwt"):
		return "api"
	case hasAny(blob, "blade", "twig", "template", "view", "xss"):
		return "template-rendering"
	case hasAny(blob, "upload", "archive", "zip", "path traversal", "lfi", "rfi", "storage"):
		return "file-system"
	case hasAny(blob, "ssrf", "curl", "guzzle", "http::", "file_get_contents", "outbound"):
		return "outbound-network"
	case hasAny(blob, "auth", "session", "cookie", "token", "password", "jwt"):
		return "identity"
	case hasAny(blob, "artisan", "command", "shell", "exec", "system", "rce"):
		return "server-execution"
	case hasAny(blob, "sql", "database", "query", "db::"):
		return "database"
	default:
		return "application-code"
	}
}

func classifyImpact(blob string, f Finding) string {
	switch {
	case hasAny(blob, "rce", "remote code execution", "command injection", "code injection", "eval", "exec", "deserialization", "cwe-78", "cwe-94", "cwe-95", "cwe-502"):
		return "remote-code-execution"
	case hasAny(blob, "secret", "credential", "private key", "api key", "password", "token leakage"):
		return "credential-exposure"
	case hasAny(blob, "supply-chain", "dependency", "composer", "npm", "install script"):
		return "supply-chain-compromise"
	case hasAny(blob, "sql injection", "information disclosure", "data exposure", "pii", "cwe-89", "cwe-200", "cwe-209"):
		return "data-exposure"
	case hasAny(blob, "idor", "privilege", "mass assignment", "authorization", "access control", "cwe-639", "cwe-862", "cwe-863", "cwe-915"):
		return "privilege-escalation"
	case hasAny(blob, "ssrf", "server-side request forgery"):
		return "internal-service-access"
	case hasAny(blob, "xss", "cross-site scripting"):
		return "client-side-compromise"
	case hasAny(blob, "file upload", "path traversal", "zip slip", "lfi", "rfi"):
		return "arbitrary-file-access"
	case hasAny(blob, "session", "cookie", "jwt", "csrf"):
		return "session-compromise"
	case hasAny(blob, "dos", "denial of service", "availability"):
		return "availability-loss"
	case hasAny(blob, "cryptographic", "crypto", "weak hash", "cipher"):
		return "cryptographic-weakness"
	case hasAny(blob, "misconfiguration", "debug", "logging", "monitoring"):
		return "security-control-weakness"
	default:
		if f.Severity >= SeverityHigh {
			return "high-risk-weakness"
		}
		return "security-weakness"
	}
}

func classifyCompliance(f Finding) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(value string) {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}

	add(f.CWE)
	add(f.OWASP)
	for _, tag := range f.Tags {
		t := strings.TrimSpace(tag)
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "cwe-"):
			add(t)
		case strings.HasPrefix(lower, "owasp-"):
			add(t)
		case strings.HasPrefix(lower, "a0") || strings.HasPrefix(lower, "a1"):
			add(t)
		case strings.HasPrefix(lower, "pci-dss"), strings.HasPrefix(lower, "nist"), strings.HasPrefix(lower, "iso-"), strings.HasPrefix(lower, "cis-"), strings.HasPrefix(lower, "soc2"):
			add(t)
		}
	}

	return out
}

func hasAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func normalizeClassificationValue(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}

	replacer := strings.NewReplacer(
		"&", " ",
		"/", " ",
		"(", " ",
		")", " ",
		":", " ",
		"_", "-",
	)
	value = replacer.Replace(value)
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, "-")
}
