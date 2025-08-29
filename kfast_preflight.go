//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func init() {
	// kubectl presence
	if _, err := exec.LookPath("kubectl"); err != nil {
		fmt.Fprintln(os.Stderr, "❌ kubectl not found in PATH.\n"+
			"   Install: https://kubernetes.io/docs/tasks/tools/\n"+
			"   Or on macOS: brew install kubectl")
		os.Exit(1)
	}
	// quick sanity (won’t hang long because your tool uses short timeouts)
	cmd := exec.Command("kubectl", "version", "--client")
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run() // non-fatal
}
