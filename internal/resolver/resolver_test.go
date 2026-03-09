package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vanguard/internal/models"
)

func TestFrameworkResolver_ComposerJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
		"name": "acme/myapp",
		"require": {
			"php": "^8.2",
			"laravel/framework": "^11.0",
			"guzzlehttp/guzzle": "^7.8"
		}
	}`), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	err := r.Resolve(context.Background(), dir, pc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pc.ProjectName != "acme/myapp" {
		t.Errorf("ProjectName = %q, want %q", pc.ProjectName, "acme/myapp")
	}
	if pc.LaravelVersion != "^11.0" {
		t.Errorf("LaravelVersion = %q, want %q", pc.LaravelVersion, "^11.0")
	}
	if pc.PHPVersion != "^8.2" {
		t.Errorf("PHPVersion = %q, want %q", pc.PHPVersion, "^8.2")
	}
	if len(pc.ComposerDeps) != 3 {
		t.Errorf("ComposerDeps count = %d, want 3", len(pc.ComposerDeps))
	}
}

func TestFrameworkResolver_EnvFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
		"name":"test/app",
		"require": {
			"laravel/framework": "^11.0"
		}
	}`), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_NAME=MyLaravelApp\nAPP_ENV=production\n"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	r.Resolve(context.Background(), dir, pc)
	if len(pc.EnvVariables) != 2 {
		t.Errorf("EnvVariables count = %d, want 2", len(pc.EnvVariables))
	}
}

func TestFrameworkResolver_PackageJSONDoesNotOverrideDetectedPHPFramework(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
		"require": {
			"laravel/framework": "^11.0"
		}
	}`), 0644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
		"name": "frontend-shell",
		"dependencies": {
			"react": "^19.0.0"
		}
	}`), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pc.FrameworkType != "laravel" {
		t.Fatalf("FrameworkType = %q, want laravel", pc.FrameworkType)
	}
}

func TestFrameworkResolver_FileBasedPHPFrameworkWinsOverPackageJSON(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "bin"), 0755)
	os.MkdirAll(filepath.Join(dir, "config"), 0755)
	os.WriteFile(filepath.Join(dir, "bin", "console"), []byte("#!/usr/bin/env php\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "bundles.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
		"name": "frontend-shell",
		"dependencies": {
			"react": "^19.0.0"
		}
	}`), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pc.FrameworkType != "symfony" {
		t.Fatalf("FrameworkType = %q, want symfony", pc.FrameworkType)
	}
}

func TestFrameworkResolver_ConfigDiscovery(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
		"require": {
			"laravel/framework": "^11.0"
		}
	}`), 0644)

	configDir := filepath.Join(dir, "config")
	os.MkdirAll(configDir, 0755)
	os.WriteFile(filepath.Join(configDir, "app.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(configDir, "auth.php"), []byte("<?php return [];"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	r.Resolve(context.Background(), dir, pc)

	if len(pc.ConfigFiles) != 2 {
		t.Errorf("ConfigFiles count = %d, want 2", len(pc.ConfigFiles))
	}
}

func TestFrameworkResolver_FileBasedSymfony(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "bin"), 0755)
	os.MkdirAll(filepath.Join(dir, "config"), 0755)
	os.WriteFile(filepath.Join(dir, "bin", "console"), []byte("#!/usr/bin/env php\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "bundles.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_ENV=prod\n"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.FrameworkType != "symfony" {
		t.Fatalf("FrameworkType = %q, want symfony", pc.FrameworkType)
	}
	if len(pc.ConfigFiles) != 1 || filepath.ToSlash(pc.ConfigFiles[0]) != "config/bundles.php" {
		t.Fatalf("ConfigFiles = %+v, want [config/bundles.php]", pc.ConfigFiles)
	}
}

func TestFrameworkResolver_FileBasedCakePHP(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "bin"), 0755)
	os.MkdirAll(filepath.Join(dir, "src"), 0755)
	os.MkdirAll(filepath.Join(dir, "config"), 0755)
	os.WriteFile(filepath.Join(dir, "bin", "cake"), []byte("#!/usr/bin/env php\n"), 0644)
	os.WriteFile(filepath.Join(dir, "src", "Application.php"), []byte("<?php class Application {}"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "app.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_ENV=prod\n"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.FrameworkType != "cakephp" {
		t.Fatalf("FrameworkType = %q, want cakephp", pc.FrameworkType)
	}
	if len(pc.ConfigFiles) != 1 || filepath.ToSlash(pc.ConfigFiles[0]) != "config/app.php" {
		t.Fatalf("ConfigFiles = %+v, want [config/app.php]", pc.ConfigFiles)
	}
}

func TestFrameworkResolver_FileBasedYii2(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "config"), 0755)
	os.WriteFile(filepath.Join(dir, "yii"), []byte("#!/usr/bin/env php\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "web.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_ENV=prod\n"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.FrameworkType != "yii2" {
		t.Fatalf("FrameworkType = %q, want yii2", pc.FrameworkType)
	}
	if len(pc.ConfigFiles) != 1 || filepath.ToSlash(pc.ConfigFiles[0]) != "config/web.php" {
		t.Fatalf("ConfigFiles = %+v, want [config/web.php]", pc.ConfigFiles)
	}
}

func TestFrameworkResolver_FileBasedWordPressPlugin(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "my-plugin.php"), []byte(`<?php
/**
 * Plugin Name: My Plugin
 */
defined('ABSPATH') || exit;
add_action('init', function () {});
`), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.FrameworkType != "wordpress" {
		t.Fatalf("FrameworkType = %q, want wordpress", pc.FrameworkType)
	}
}

func TestFrameworkResolver_ConfigDiscoveryRecursive(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "bin"), 0755)
	os.MkdirAll(filepath.Join(dir, "config", "packages"), 0755)
	os.WriteFile(filepath.Join(dir, "bin", "console"), []byte("#!/usr/bin/env php\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "bundles.php"), []byte("<?php return [];"), 0644)
	os.WriteFile(filepath.Join(dir, "config", "packages", "security.yaml"), []byte("security:\n  firewalls: {}\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_ENV=prod\n"), 0644)

	r := NewFrameworkResolver()
	pc := &models.ProjectContext{}
	if err := r.Resolve(context.Background(), dir, pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.FrameworkType != "symfony" {
		t.Fatalf("FrameworkType = %q, want symfony", pc.FrameworkType)
	}

	seen := map[string]bool{}
	for _, path := range pc.ConfigFiles {
		seen[filepath.ToSlash(path)] = true
	}
	if !seen["config/bundles.php"] || !seen["config/packages/security.yaml"] {
		t.Fatalf("ConfigFiles missing expected recursive entries: %+v", pc.ConfigFiles)
	}
}

func TestPackageResolver_ComposerLock(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{
		"packages": [
			{"name": "laravel/framework", "version": "v11.5.0"},
			{"name": "guzzlehttp/guzzle", "version": "7.8.1"}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "11.0.1"}
		]
	}`), 0644)

	r := NewPackageResolver()
	pc := &models.ProjectContext{}
	err := r.Resolve(context.Background(), dir, pc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pc.InstalledPackages) != 3 {
		t.Errorf("InstalledPackages count = %d, want 3", len(pc.InstalledPackages))
	}

	found := false
	for _, pkg := range pc.InstalledPackages {
		if pkg.Name == "laravel/framework" && pkg.Version == "v11.5.0" && pkg.Ecosystem == "Packagist" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("laravel/framework version v11.5.0 not found in installed packages")
	}
}

func TestPackageResolver_NoLockFile(t *testing.T) {
	dir := t.TempDir()

	r := NewPackageResolver()
	pc := &models.ProjectContext{}
	err := r.Resolve(context.Background(), dir, pc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pc.InstalledPackages) != 0 {
		t.Errorf("InstalledPackages should be empty, got %d", len(pc.InstalledPackages))
	}
}
