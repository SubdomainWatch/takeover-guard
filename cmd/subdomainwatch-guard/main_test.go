package main

import (
	"encoding/json"
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

func TestCLIExitZeroOnIndeterminateTargetInBothFailModes(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "subdomainwatch-guard")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, string(out))
	}

	planJSON := `{
  "resource_changes": [
    {
      "address": "cloudflare_record.test",
      "type": "cloudflare_record",
      "change": {
        "actions": ["create"],
        "after": {
          "name": "transient.dummy-nonexistent-subdomainwatch.com",
          "type": "CNAME",
          "content": "unresolvable-target-123456.s3.amazonaws.com"
        }
      }
    }
  ]
}`
	planFile := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planFile, []byte(planJSON), 0644); err != nil {
		t.Fatal(err)
	}

	jsonFileClosed := filepath.Join(t.TempDir(), "report_closed.json")
	// 1. In fail-mode=closed, indeterminate external probe MUST exit 0 (transient indeterminate outcome does not fail build)
	cmdClosed := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "closed",
		"-json-file", jsonFileClosed,
	)
	cmdClosed.Env = append(os.Environ(), "GUARD_MOCK_PROBE_STATUS=INDETERMINATE")
	outClosed, errClosed := cmdClosed.CombinedOutput()
	if errClosed != nil {
		t.Fatalf("expected exit 0 for fail-mode=closed with indeterminate target, got %v\nOutput: %s", errClosed, string(outClosed))
	}

	// Verify json report contains indeterminate_count = 1 and 0 findings
	dataClosed, err := os.ReadFile(jsonFileClosed)
	if err != nil {
		t.Fatal(err)
	}
	var reportClosed struct {
		IndeterminateCount int `json:"indeterminate_count"`
		CriticalCount      int `json:"critical_count"`
		HighCount          int `json:"high_count"`
		WarningCount       int `json:"warning_count"`
	}
	if err := json.Unmarshal(dataClosed, &reportClosed); err != nil {
		t.Fatal(err)
	}
	if reportClosed.IndeterminateCount != 1 {
		t.Errorf("expected indeterminate_count = 1, got %d", reportClosed.IndeterminateCount)
	}
	if reportClosed.CriticalCount != 0 || reportClosed.HighCount != 0 || reportClosed.WarningCount != 0 {
		t.Errorf("expected 0 confirmed findings, got crit=%d high=%d warn=%d", reportClosed.CriticalCount, reportClosed.HighCount, reportClosed.WarningCount)
	}

	// 2. In fail-mode=open, indeterminate target MUST also exit 0
	cmdOpen := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "open",
	)
	cmdOpen.Env = append(os.Environ(), "GUARD_MOCK_PROBE_STATUS=INDETERMINATE")
	outOpen, errOpen := cmdOpen.CombinedOutput()
	if errOpen != nil {
		t.Fatalf("expected exit 0 for fail-mode=open with indeterminate target, got %v\nOutput: %s", errOpen, string(outOpen))
	}
}

func TestCLIExitOneOnConfirmedFindingInClosedMode(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "subdomainwatch-guard")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, string(out))
	}

	planJSON := `{
  "resource_changes": [
    {
      "address": "cloudflare_record.vuln",
      "type": "cloudflare_record",
      "change": {
        "actions": ["create"],
        "after": {
          "name": "takeover.dummy-subdomainwatch.com",
          "type": "CNAME",
          "content": "unclaimed-bucket.s3.amazonaws.com"
        }
      }
    }
  ]
}`
	planFile := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planFile, []byte(planJSON), 0644); err != nil {
		t.Fatal(err)
	}

	jsonFileClosed := filepath.Join(t.TempDir(), "report_confirmed_closed.json")
	// 1. In fail-mode=closed, confirmed takeover finding MUST exit 1
	cmdClosed := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "closed",
		"-json-file", jsonFileClosed,
	)
	cmdClosed.Env = append(os.Environ(), "GUARD_MOCK_PROBE_STATUS=CONFIRMED")
	outClosed, errClosed := cmdClosed.CombinedOutput()
	exitErr, ok := errClosed.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 for fail-mode=closed with confirmed finding, got err=%v exit=%v\nOutput: %s", errClosed, exitErr, string(outClosed))
	}

	// Verify json report contains confirmed findings
	dataClosed, err := os.ReadFile(jsonFileClosed)
	if err != nil {
		t.Fatal(err)
	}
	var reportClosed struct {
		IndeterminateCount int `json:"indeterminate_count"`
		CriticalCount      int `json:"critical_count"`
		HighCount          int `json:"high_count"`
	}
	if err := json.Unmarshal(dataClosed, &reportClosed); err != nil {
		t.Fatal(err)
	}
	if reportClosed.CriticalCount == 0 && reportClosed.HighCount == 0 {
		t.Errorf("expected confirmed findings > 0, got crit=%d high=%d", reportClosed.CriticalCount, reportClosed.HighCount)
	}

	// 2. In fail-mode=open, confirmed takeover finding MUST exit 0 (warning mode)
	cmdOpen := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "open",
	)
	cmdOpen.Env = append(os.Environ(), "GUARD_MOCK_PROBE_STATUS=CONFIRMED")
	outOpen, errOpen := cmdOpen.CombinedOutput()
	if errOpen != nil {
		t.Fatalf("expected exit 0 for fail-mode=open with confirmed finding, got %v\nOutput: %s", errOpen, string(outOpen))
	}
}
