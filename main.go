package main

import (
	"os"

	"github.com/haliminurja/vanguard/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
