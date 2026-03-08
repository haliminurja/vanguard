package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const vanguardDir = ".vanguard"

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, vanguardDir), nil
}
func FilePath(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
func SubDir(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("creating %s: %w", path, err)
	}
	return path, nil
}
func EnsureDir() error {
	dir, err := Dir()
	if err != nil {
		return err
	}

	dirs := []string{
		dir,
		filepath.Join(dir, "cache"),
		filepath.Join(dir, "reports"),
		filepath.Join(dir, "store"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("creating %s: %w", d, err)
		}
	}

	return nil
}
func ReportsDir() (string, error) {
	return SubDir("reports")
}
func StoreDir() (string, error) {
	return SubDir("store")
}
