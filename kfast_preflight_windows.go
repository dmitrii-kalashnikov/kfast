//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func init() {
	if _, err := exec.LookPath("kubectl.exe"); err != nil {
		fmt.Fprintln(os.Stderr, "❌ kubectl.exe not found in PATH.\n"+
			"   Install: https://kubernetes.io/docs/tasks/tools/")
		os.Exit(1)
	}
}
