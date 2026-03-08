package updater

import (
	"fmt"
)

// CheckForUpdate is a placeholder for the update check logic.
// It returns an empty string if no update is available.
func CheckForUpdate(version string, configDir string) string {
	// For now, we return empty to avoid annoying the user with update prompts
	// during the rebranding phase.
	return ""
}

func PrintUpdateNotice(notice string) {
	if notice != "" {
		fmt.Println(notice)
	}
}
