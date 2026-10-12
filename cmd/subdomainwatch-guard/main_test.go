package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGitHubOutputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-output")
	t.Setenv("GITHUB_OUTPUT", path)
	writeGitHubOutputs("guard.sarif", 7)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "sarif_file=guard.sarif\nfindings_count=7\n" {
		t.Fatalf("unexpected outputs: %q", got)
	}
}

func TestExitConfigFailUsesCodeTwo(t *testing.T) {
	if os.Getenv("GUARD_EXIT_CONFIG_FAIL_CHILD") == "1" {
		exitConfigFail("closed", "expected config failure\n")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestExitConfigFailUsesCodeTwo")
	cmd.Env = append(os.Environ(), "GUARD_EXIT_CONFIG_FAIL_CHILD=1")
	output, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected child exit 2, got err=%v output=%q", err, output)
	}
	if !strings.Contains(string(output), "expected config failure") {
		t.Fatalf("expected diagnostic on stderr, got %q", output)
	}
}
