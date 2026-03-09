package reporter

import (
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vanguard/internal/models"
)

type HTMLReporter struct {
	OutputDir string
	Version   string
}

func NewHTMLReporter(outputDir string, version string) *HTMLReporter {
	if outputDir == "" {
		outputDir = "."
	}
	if version == "" {
		version = "dev"
	}
	return &HTMLReporter{OutputDir: outputDir, Version: version}
}

func (r *HTMLReporter) Name() string   { return "html" }
func (r *HTMLReporter) Format() string { return "html" }

func (r *HTMLReporter) Generate(_ context.Context, report *models.ScanReport) error {
	counts := report.CountBySeverity()
	byCategory := report.FindingsByCategory()
	categories := make([]string, 0, len(byCategory))
	for cat := range byCategory {
		categories = append(categories, cat)
	}
	sort.Slice(categories, func(i, j int) bool {
		maxI := maxSeverity(byCategory[categories[i]])
		maxJ := maxSeverity(byCategory[categories[j]])
		if maxI != maxJ {
			return maxI > maxJ
		}
		return categories[i] < categories[j]
	})

	total := len(report.Findings)

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VANGUARD &middot; Defense Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
`)
	sb.WriteString(htmlCSS)
	sb.WriteString(`
</style>
</head>
<body>
`)
	sb.WriteString(`<aside class="sidebar">
  <div class="sidebar-logo">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <span>VANGUARD</span>
  </div>
  <nav class="toc">
    <div class="toc-group">
      <div class="toc-title">General</div>
      <a href="#overview" class="toc-link">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
        Overview
      </a>
      <a href="#project" class="toc-link">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
        Project Info
      </a>
    </div>
    <div class="toc-group">
      <div class="toc-title">Findings</div>
`)
	for _, cat := range categories {
		slug := categorySlug(cat)
		count := len(byCategory[cat])
		sb.WriteString(fmt.Sprintf(`      <a href="#cat-%s" class="toc-link">
        <span class="toc-cat-name">%s</span>
        <span class="toc-count">%d</span>
      </a>
`, slug, esc(cat), count))
	}

	sb.WriteString(`    </div>
  </nav>
  <div class="sidebar-footer">
    <div class="author">By <a href="https://github.com/haliminurja/vanguard" style="color:inherit;text-decoration:none"><strong>haliminurja</strong></a></div>
    <div class="version">Version ` + r.Version + `</div>
  </div>
</aside>
`)
	sb.WriteString(`<main class="main">
`)
	sb.WriteString(`<header class="header">
  <div class="header-content">
    <h1>Vanguard Defense Report</h1>
    <div class="header-badges">
      <span class="header-badge project">` + esc(report.ProjectContext.ProjectName) + `</span>
      <span class="header-badge framework">Laravel ` + esc(report.ProjectContext.LaravelVersion) + `</span>
      <span class="header-badge time">` + report.Duration.Round(1e6).String() + `</span>
    </div>
  </div>
</header>
`)
	sb.WriteString(`<section id="overview" class="section">
  <div class="section-header">
    <h2 class="section-title">Scan Overview</h2>
  </div>
  <div class="stats-grid">
`)
	sb.WriteString(fmt.Sprintf(`    <div class="stat-card total"><div class="stat-label">Total Findings</div><div class="stat-num">%d</div></div>
`, total))
	for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		c := counts[sev]
		cls := strings.ToLower(sev.String())
		sb.WriteString(fmt.Sprintf(`    <div class="stat-card %s"><div class="stat-label">%s</div><div class="stat-num">%d</div></div>
`, cls, sev.String(), c))
	}
	sb.WriteString(`  </div>
`)
	if total > 0 {
		sb.WriteString(`  <div class="severity-bar-container">
    <div class="severity-bar">
`)
		for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
			c := counts[sev]
			if c == 0 {
				continue
			}
			pct := float64(c) / float64(total) * 100
			cls := strings.ToLower(sev.String())
			sb.WriteString(fmt.Sprintf(`      <div class="bar-seg %s" style="width:%.1f%%" title="%d %s"></div>
`, cls, pct, c, sev.String()))
		}
		sb.WriteString(`    </div>
  </div>
`)
	}
	sb.WriteString(`</section>
`)

	score := report.VanguardDefenseRating()
	grade := report.DefenseGrade()
	gradeClass := "grade-a"
	switch grade {
	case "B", "C":
		gradeClass = "grade-b"
	case "D":
		gradeClass = "grade-d"
	case "F":
		gradeClass = "grade-f"
	}

	sb.WriteString(fmt.Sprintf(`<section id="score" class="section">
  <div class="section-header">
    <h2 class="section-title">Defense Rating</h2>
  </div>
  <div class="score-card">
    <div class="score-main">
      <div class="score-circle %s" style="--score-pct: %d%%">
        <svg viewBox="0 0 36 36" class="circular-chart">
          <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          <path class="circle" stroke-dasharray="%d, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          <text x="18" y="20.35" class="percentage">%d</text>
        </svg>
        <div class="grade-label">%s</div>
      </div>
      <div class="score-info">
        <h3>Proyek Anda mendapatkan Rating %s</h3>
        <p>Skor ini dihitung berdasarkan jumlah dan tingkat keparahan celah keamanan yang ditemukan dibandingkan dengan ukuran proyek.</p>
      </div>
    </div>
  </div>
</section>
`, gradeClass, score, score, score, grade, grade))

	sb.WriteString(`</section>
`)
	sb.WriteString(`<section id="project" class="section">
  <div class="section-header">
    <h2 class="section-title">Project Context</h2>
  </div>
  <div class="info-grid">
`)
	writeInfoRow(&sb, "Project Name", report.ProjectContext.ProjectName)
	writeInfoRow(&sb, "Laravel Version", report.ProjectContext.LaravelVersion)
	writeInfoRow(&sb, "PHP Version", report.ProjectContext.PHPVersion)
	writeInfoRow(&sb, "Scanned Packages", fmt.Sprintf("%d dependencies", len(report.ProjectContext.InstalledPackages)))
	writeInfoRow(&sb, "Config Files", fmt.Sprintf("%d files analyzed", len(report.ProjectContext.ConfigFiles)))
	writeInfoRow(&sb, "Analysis Time", report.Duration.Round(1e6).String())
	sb.WriteString(`  </div>
</section>
`)

	for _, cat := range categories {
		slug := categorySlug(cat)
		findings := byCategory[cat]
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Severity.Weight() > findings[j].Severity.Weight()
		})

		sb.WriteString(fmt.Sprintf(`<section id="cat-%s" class="section">
  <div class="section-header">
    <h2 class="section-title">%s</h2>
    <span class="count-badge">%d</span>
  </div>
  <div class="findings-list">
`, slug, esc(cat), len(findings)))

		for idx, f := range findings {
			sevClass := strings.ToLower(f.Severity.String())
			findingID := fmt.Sprintf("%s-%d", slug, idx)

			sb.WriteString(fmt.Sprintf(`    <div class="finding-card" id="%s">
      <div class="finding-header" onclick="this.parentElement.classList.toggle('is-open')">
        <div class="status-indicator %s"></div>
        <div class="finding-main">
          <div class="finding-top">
            <span class="severity-tag %s">%s</span>
            <span class="finding-id">%s</span>
          </div>
          <h3 class="finding-title">%s</h3>
          <div class="finding-meta">
            <span class="loc">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>
              %s:%d
            </span>
          </div>
        </div>
        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="finding-content">
        <div class="content-inner">
          <div class="desc-group">
            <h4>Description</h4>
            <p>%s</p>
          </div>
`, findingID, sevClass, sevClass, f.Severity.String(), esc(f.ID), esc(f.Title), esc(f.File), f.Line, esc(f.Description)))

			if f.CodeSnippet != "" {
				sb.WriteString(`          <div class="code-group">
            <h4>Code Snippet</h4>
            <div class="code-window">
              <div class="code-header">
                <div class="dots"><span></span><span></span><span></span></div>
                <div class="file-name">` + esc(filepath.Base(f.File)) + `</div>
              </div>
              <div class="code-body">
`)
				if len(f.ContextBefore) > 0 || len(f.ContextAfter) > 0 {
					startLine := f.Line - len(f.ContextBefore)
					for i, line := range f.ContextBefore {
						sb.WriteString(fmt.Sprintf(`                <div class="code-line"><span class="ln">%d</span><span class="cl">%s</span></div>`, startLine+i, esc(line)))
					}
					sb.WriteString(fmt.Sprintf(`                <div class="code-line highlight"><span class="ln">%d</span><span class="cl">%s</span></div>`, f.Line, esc(f.CodeSnippet)))
					for i, line := range f.ContextAfter {
						sb.WriteString(fmt.Sprintf(`                <div class="code-line"><span class="ln">%d</span><span class="cl">%s</span></div>`, f.Line+i+1, esc(line)))
					}
				} else {
					sb.WriteString(fmt.Sprintf(`                <div class="code-line highlight"><span class="ln">%d</span><span class="cl">%s</span></div>`, f.Line, esc(f.CodeSnippet)))
				}
				sb.WriteString(`              </div>
            </div>
          </div>
`)
			}

			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf(`          <div class="remediation-group">
            <h4><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> Remediation</h4>
            <div class="remediation-box">%s</div>
          </div>
`, esc(f.Remediation)))
			}

			if len(f.References) > 0 {
				sb.WriteString(`          <div class="refs-group">
            <h4>References</h4>
            <ul>
`)
				for _, ref := range f.References {
					sb.WriteString(fmt.Sprintf(`              <li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, esc(ref), esc(ref)))
				}
				sb.WriteString(`            </ul>
          </div>
`)
			}

			hasMetadata := len(f.Tags) > 0 || f.CWE != "" || f.OWASP != "" || f.Confidence != "" || f.CVSSScore > 0 || f.CVSSVector != ""
			if hasMetadata {
				sb.WriteString(`          <div class="metadata-group">
            <h4>Metadata</h4>
            <div class="meta-pills">
`)
				if f.CVSSScore > 0 {
					sb.WriteString(fmt.Sprintf(`              <span class="meta-pill cvss-pill">CVSS: %.1f</span>
`, f.CVSSScore))
				}
				if f.CVSSVector != "" {
					sb.WriteString(fmt.Sprintf(`              <span class="meta-pill cvss-vector-pill" title="CVSS Vector">%s</span>
`, f.CVSSVector))
				}
				if f.CWE != "" {
					cweNum := strings.TrimPrefix(strings.ToUpper(f.CWE), "CWE-")
					sb.WriteString(fmt.Sprintf(`              <a href="https://cwe.mitre.org/data/definitions/%s.html" target="_blank" class="meta-pill cwe-pill">%s</a>
`, cweNum, strings.ToUpper(f.CWE)))
				}
				if f.OWASP != "" {
					sb.WriteString(fmt.Sprintf(`              <span class="meta-pill">%s</span>
`, esc(strings.ToUpper(f.OWASP))))
				}
				if f.Confidence != "" {
					sb.WriteString(fmt.Sprintf(`              <span class="meta-pill conf-%s">⚡ %s confidence</span>
`, f.Confidence, f.Confidence))
				}
				for _, tag := range f.Tags {
					if !strings.HasPrefix(tag, "cwe-") {
						sb.WriteString(fmt.Sprintf(`              <span class="meta-pill tag-pill">%s</span>
`, esc(tag)))
					}
				}
				sb.WriteString(`            </div>
          </div>
`)
			}

			sb.WriteString(`        </div>
      </div>
    </div>
`)
		}
		sb.WriteString(`  </div>
</section>
`)
	}

	sb.WriteString(`<footer class="page-footer">
  <div class="footer-logo">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <span>VANGUARD</span>
  </div>
  <p>Proyek Keamanan oleh <a href="https://github.com/haliminurja/vanguard">Ahmad Halimi</a> &middot; &copy; 2025</p>
</footer>
</main>
</body>
</html>`)

	outPath := filepath.Join(r.OutputDir, "vanguard-report.html")
	if err := os.WriteFile(outPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("writing HTML report to %s: %w", outPath, err)
	}

	return nil
}

func esc(s string) string {
	return html.EscapeString(s)
}

func categorySlug(cat string) string {
	s := strings.ToLower(cat)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

func maxSeverity(findings []models.Finding) int {
	max := 0
	for _, f := range findings {
		if w := f.Severity.Weight(); w > max {
			max = w
		}
	}
	return max
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func writeInfoRow(sb *strings.Builder, label, value string) {
	sb.WriteString(fmt.Sprintf(`    <div class="info-row"><span class="info-label">%s</span><span class="info-value">%s</span></div>
`, label, esc(value)))
}

const htmlCSS = `
  :root {
    --bg: #0f172a;
    --sidebar-bg: rgba(15, 23, 42, 0.8);
    --surface: rgba(30, 41, 59, 0.4);
    --surface-hover: rgba(30, 41, 59, 0.6);
    --border: rgba(51, 65, 85, 0.5);
    --text: #94a3b8;
    --text-bright: #f8fafc;
    --text-dim: #64748b;
    --primary: #6366f1;
    --primary-glow: rgba(99, 102, 241, 0.2);
    --accent: #8b5cf6;
    
    --critical: #f43f5e;
    --high: #f97316;
    --medium: #f59e0b;
    --low: #10b981;
    --info: #3b82f6;
    
    --radius-lg: 16px;
    --radius-md: 12px;
    --radius-sm: 8px;
    --sidebar-w: 280px;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background-color: var(--bg);
    background-image: 
      radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
      radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.1) 0px, transparent 50%);
    color: var(--text);
    line-height: 1.6;
    display: flex;
    min-height: 100vh;
  }

  /* Sidebar Glassmorphism */
  .sidebar {
    position: fixed;
    top: 0; left: 0; bottom: 0;
    width: var(--sidebar-w);
    background: var(--sidebar-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-right: 1px solid var(--border);
    padding: 40px 24px;
    display: flex;
    flex-direction: column;
    z-index: 100;
  }

  .sidebar-logo {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--text-bright);
    font-weight: 800;
    font-size: 20px;
    letter-spacing: 2px;
    margin-bottom: 48px;
  }
  .sidebar-logo fill { color: var(--primary); }

  .toc-group { margin-bottom: 32px; }
  .toc-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--text-dim);
    margin-bottom: 12px;
    font-weight: 700;
  }

  .toc-link {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    margin-bottom: 4px;
    border-radius: var(--radius-sm);
    color: var(--text);
    text-decoration: none;
    font-size: 13px;
    font-weight: 500;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .toc-link svg { margin-right: 10px; opacity: 0.6; }
  .toc-link:hover {
    background: var(--surface);
    color: var(--text-bright);
    transform: translateX(4px);
  }
  .toc-link:hover svg { opacity: 1; color: var(--primary); }

  .toc-count {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    background: var(--primary-glow);
    color: var(--primary);
    padding: 2px 8px;
    border-radius: 10px;
  }

  .sidebar-footer {
    margin-top: auto;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    font-size: 12px;
  }
  .sidebar-footer .author { color: var(--text-bright); margin-bottom: 4px; }
  .sidebar-footer .version { color: var(--text-dim); }

  /* Main Content Area */
  .main {
    margin-left: var(--sidebar-w);
    flex: 1;
    padding: 60px 80px;
    max-width: 1200px;
  }

  .header { margin-bottom: 64px; }
  .header h1 {
    font-size: 42px;
    font-weight: 800;
    color: var(--text-bright);
    letter-spacing: -1px;
    margin-bottom: 16px;
  }
  .header-badges { display: flex; gap: 12px; }
  .header-badge {
    padding: 6px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 30px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-dim);
  }
  .header-badge.project { border-color: var(--primary); color: var(--primary); }

  /* Sections */
  .section { margin-bottom: 80px; scroll-margin-top: 40px; }
  .section-header { 
    display: flex; 
    align-items: center; 
    justify-content: space-between;
    margin-bottom: 28px;
  }
  .section-title {
    font-size: 24px;
    font-weight: 700;
    color: var(--text-bright);
    letter-spacing: -0.5px;
  }

  /* Stats Grid */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 20px;
    margin-bottom: 32px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 24px;
    transition: all 0.3s ease;
  }
  .stat-card:hover {
    transform: translateY(-8px);
    border-color: var(--primary);
    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
  }
  .stat-label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); margin-bottom: 8px; }
  .stat-num { font-size: 36px; font-weight: 800; color: var(--text-bright); }
  
  .stat-card.critical .stat-num { color: var(--critical); }
  .stat-card.high .stat-num { color: var(--high); }
  .stat-card.medium .stat-num { color: var(--medium); }
  .stat-card.low .stat-num { color: var(--low); }

  /* Severity Bar */
  .severity-bar-container {
    height: 12px;
    background: var(--surface);
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .severity-bar { display: flex; height: 100%; }
  .bar-seg.critical { background: var(--critical); box-shadow: 0 0 10px var(--critical); }
  .bar-seg.high { background: var(--high); }
  .bar-seg.medium { background: var(--medium); }
  .bar-seg.low { background: var(--low); }

  /* Score Area */
  .score-card {
    background: var(--surface);
    border-radius: var(--radius-lg);
    padding: 40px;
    border: 1px solid var(--border);
  }
  .score-main { display: flex; align-items: center; gap: 48px; }
  
  .score-circle { position: relative; width: 140px; height: 140px; }
  .circular-chart { display: block; margin: 10px auto; max-width: 100%; max-height: 250px; }
  .circle-bg { fill: none; stroke: var(--border); stroke-width: 2.8; }
  .circle { fill: none; stroke-width: 2.8; stroke-linecap: round; transition: stroke-dasharray 1s ease; }
  
  .grade-a .circle { stroke: var(--low); }
  .grade-b .circle { stroke: var(--medium); }
  .grade-d .circle { stroke: var(--high); }
  .grade-f .circle { stroke: var(--critical); }

  .percentage { fill: var(--text-bright); font-family: 'Inter', sans-serif; font-size: 0.5em; text-anchor: middle; font-weight: 800; }
  .grade-label {
    position: absolute;
    bottom: -10px; left: 50%;
    transform: translateX(-50%);
    background: var(--primary);
    color: white;
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: 800;
    font-size: 14px;
    box-shadow: 0 4px 12px var(--primary-glow);
  }

  .score-info h3 { font-size: 20px; color: var(--text-bright); margin-bottom: 12px; }
  .score-info p { max-width: 500px; color: var(--text-dim); }

  /* Findings List */
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    margin-bottom: 20px;
    transition: all 0.3s ease;
    overflow: hidden;
  }
  .finding-card:hover { border-color: var(--primary); }
  .finding-card.is-open { border-color: var(--primary); background: rgba(30, 41, 59, 0.6); }

  .finding-header {
    padding: 24px;
    display: flex;
    align-items: center;
    gap: 20px;
    cursor: pointer;
    user-select: none;
  }
  
  .status-indicator { width: 4px; height: 40px; border-radius: 4px; flex-shrink: 0; }
  .status-indicator.critical { background: var(--critical); box-shadow: 0 0 15px var(--critical); }
  .status-indicator.high { background: var(--high); }
  .status-indicator.medium { background: var(--medium); }
  .status-indicator.low { background: var(--low); }

  .finding-main { flex: 1; }
  .finding-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .severity-tag {
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 4px 10px;
    border-radius: 4px;
    color: white;
  }
  .severity-tag.critical { background: var(--critical); }
  .severity-tag.high { background: var(--high); }
  .severity-tag.medium { background: var(--medium); color: var(--bg); }
  .severity-tag.low { background: var(--low); }

  .finding-id { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-dim); }
  .finding-title { font-size: 17px; font-weight: 700; color: var(--text-bright); }
  
  .finding-meta { display: flex; gap: 16px; margin-top: 8px; }
  .loc { font-size: 12px; color: var(--text-dim); display: flex; align-items: center; gap: 6px; }

  .chevron { transition: transform 0.3s ease; color: var(--text-dim); }
  .finding-card.is-open .chevron { transform: rotate(180deg); color: var(--primary); }

  .finding-content {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .finding-card.is-open .finding-content { max-height: 2000px; }
  
  .content-inner { padding: 0 24px 32px 88px; }
  
  .content-inner h4 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-bright);
    margin: 24px 0 12px 0;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .desc-group p { font-size: 15px; color: var(--text); }

  /* Code Window */
  .code-window {
    background: #0d1117;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    overflow: hidden;
  }
  .code-header {
    background: #161b22;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
  }
  .dots { display: flex; gap: 6px; }
  .dots span { width: 8px; height: 8px; border-radius: 50%; background: #30363d; }
  .file-name { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-dim); }
  
  .code-body { padding: 16px 0; font-family: 'JetBrains Mono', monospace; font-size: 13px; overflow-x: auto; }
  .code-line { display: flex; padding: 0 16px; }
  .code-line.highlight { background: rgba(99, 102, 241, 0.15); border-left: 3px solid var(--primary); }
  .ln { min-width: 40px; color: #484f58; text-align: right; padding-right: 16px; user-select: none; }
  .cl { color: #e6edf3; white-space: pre; }

  /* Remediation Box */
  .remediation-box {
    background: var(--primary-glow);
    border: 1px solid var(--primary);
    border-radius: var(--radius-sm);
    padding: 20px;
    color: var(--text-bright);
    font-size: 14px;
    white-space: pre-wrap;
  }

  .refs-group ul { list-style: none; }
  .refs-group li { margin-bottom: 6px; }
  .refs-group a { color: var(--primary); text-decoration: none; font-size: 13px; }
  .refs-group a:hover { text-decoration: underline; }

  /* Footer */
  .page-footer {
    margin-top: 100px;
    padding-top: 40px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-dim);
    font-size: 14px;
  }
  .footer-logo { display: flex; align-items: center; justify-content: center; gap: 10px; color: var(--text-bright); font-weight: 800; margin-bottom: 12px; opacity: 0.5; }
  .page-footer a { color: var(--primary); text-decoration: none; font-weight: 600; }

  @media (max-width: 1024px) {
    .sidebar { display: none; }
    .main { margin-left: 0; padding: 40px 24px; }
    .score-main { flex-direction: column; text-align: center; }
    .content-inner { padding: 0 24px 32px 24px; }
  }
`
