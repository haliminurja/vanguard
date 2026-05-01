package resolver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/haliminurja/vanguard/internal/models"
)

type PackageResolver struct{}

func NewPackageResolver() *PackageResolver {
	return &PackageResolver{}
}

func (r *PackageResolver) Name() string  { return "packages" }
func (r *PackageResolver) Priority() int { return 20 }

func (r *PackageResolver) Resolve(_ context.Context, root string, pc *models.ProjectContext) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		if name != "composer.lock" && name != "package-lock.json" && name != "yarn.lock" && name != "pnpm-lock.yaml" {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		if relPath == "" {
			relPath = name
		}

		switch name {
		case "composer.lock":
			r.resolveComposer(path, relPath, pc)
		case "package-lock.json":
			r.resolveNPM(path, relPath, pc)
		case "yarn.lock":
			r.resolveYarn(path, relPath, pc)
		case "pnpm-lock.yaml":
			r.resolvePNPM(path, relPath, pc)
		}

		return nil
	})
}

func (r *PackageResolver) resolveComposer(path string, relPath string, pc *models.ProjectContext) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return
	}

	for _, pkg := range lock.Packages {
		pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "Packagist",
			File:      relPath,
		})
	}
	for _, pkg := range lock.PackagesDev {
		pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "Packagist",
			File:      relPath,
		})
	}
}

func (r *PackageResolver) resolveNPM(path string, relPath string, pc *models.ProjectContext) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return
	}
	if len(lock.Packages) > 0 {
		for p, pkg := range lock.Packages {
			if p == "" || pkg.Version == "" {
				continue
			}
			name := packageNameFromNPMLockPath(p)
			if name == "" {
				continue
			}
			pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				File:      relPath,
			})
		}
	} else if len(lock.Dependencies) > 0 {
		for name, pkg := range lock.Dependencies {
			pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				File:      relPath,
			})
		}
	}
}

func (r *PackageResolver) resolveYarn(path string, relPath string, pc *models.ProjectContext) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	var currentPkg string

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			namePart := strings.TrimSuffix(line, ":")
			namePart = strings.Trim(namePart, "\"")
			currentPkg = packageNameFromYarnSelector(namePart)
		} else if currentPkg != "" && strings.HasPrefix(line, "  version ") {
			versionPart := strings.TrimPrefix(line, "  version ")
			version := strings.Trim(versionPart, "\"")
			found := false
			for _, existing := range pc.InstalledPackages {
				if existing.Name == currentPkg && existing.Version == version && existing.Ecosystem == "npm" && existing.File == relPath {
					found = true
					break
				}
			}

			if !found {
				pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
					Name:      currentPkg,
					Version:   version,
					Ecosystem: "npm",
					File:      relPath,
				})
			}

			currentPkg = ""
		}
	}
}

func (r *PackageResolver) resolvePNPM(path string, relPath string, pc *models.ProjectContext) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	inPackages := false

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		if line == "packages:" {
			inPackages = true
			continue
		}

		if inPackages && !strings.HasPrefix(line, " ") && line != "" {
			inPackages = false
			continue
		}

		if inPackages && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			raw := strings.TrimSpace(line)
			raw = strings.TrimSuffix(raw, ":")
			raw = strings.TrimPrefix(raw, "/")
			if idx := strings.Index(raw, "("); idx > 0 {
				raw = raw[:idx]
			}

			lastAt := strings.LastIndex(raw, "@")
			if lastAt > 0 {
				name := raw[:lastAt]
				version := raw[lastAt+1:]

				pc.InstalledPackages = append(pc.InstalledPackages, models.Package{
					Name:      name,
					Version:   version,
					Ecosystem: "npm",
					File:      relPath,
				})
			}
		}
	}
}

func packageNameFromNPMLockPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "./")
	if path == "" {
		return ""
	}

	const marker = "node_modules/"
	if idx := strings.LastIndex(path, marker); idx >= 0 {
		return path[idx+len(marker):]
	}
	return path
}

func packageNameFromYarnSelector(selector string) string {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return ""
	}

	first := selector
	if idx := strings.Index(first, ","); idx >= 0 {
		first = first[:idx]
	}
	first = strings.TrimSpace(strings.Trim(first, `"'`))
	if first == "" {
		return ""
	}

	if strings.HasPrefix(first, "@") {
		slash := strings.Index(first, "/")
		if slash < 0 {
			return first
		}
		versionAt := strings.LastIndex(first[slash+1:], "@")
		if versionAt < 0 {
			return first
		}
		return first[:slash+1+versionAt]
	}

	if idx := strings.LastIndex(first, "@"); idx > 0 {
		return first[:idx]
	}
	return first
}

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type npmLock struct {
	Packages     map[string]npmPackage `json:"packages"`
	Dependencies map[string]npmPackage `json:"dependencies"`
}

type npmPackage struct {
	Version string `json:"version"`
}
