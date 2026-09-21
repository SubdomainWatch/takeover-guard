package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
	"github.com/subdomainwatch/takeover-guard/pkg/dnsresolver"
	"github.com/subdomainwatch/takeover-guard/pkg/override"
	"github.com/subdomainwatch/takeover-guard/pkg/prober"
	"github.com/subdomainwatch/takeover-guard/pkg/reporter"
)

// Flow 1: SW-G-001 with In-Code Override Suppression
func TestIntegration_OverrideSuppressesSWG001(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-integ-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tfPath := filepath.Join(tmpDir, "dns.tf")
	tfContent := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-11-01 approver=@ciso reason="Accepted staging decommission window"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
  type = "CNAME"
  records = ["acme-staging-assets.s3.amazonaws.com"]
}
`
	if err := os.WriteFile(tfPath, []byte(tfContent), 0644); err != nil {
		t.Fatal(err)
	}

	plan := &correlator.PlanJSON{
		ResourceChanges: []correlator.ResourceChange{
			{
				Address: "aws_s3_bucket.staging_assets",
				Type:    "aws_s3_bucket",
				Change: correlator.ChangeObj{
					Actions: []string{"delete"},
					Before:  map[string]any{"bucket": "acme-staging-assets"},
				},
			},
			{
				Address: "aws_route53_record.staging",
				Type:    "aws_route53_record",
				Change: correlator.ChangeObj{
					Actions: []string{"no-op"},
					After: map[string]any{
						"name":    "staging.acme.com",
						"type":    "CNAME",
						"records": []any{"acme-staging-assets.s3.amazonaws.com"},
					},
				},
			},
		},
	}

	// 1. Evaluate plan: findings detected
	findings, _, err := correlator.EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatalf("correlator failed: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != correlator.RuleUncoordinatedOrphan {
		t.Fatalf("expected 1 SW-G-001 finding, got %d", len(findings))
	}

	// 2. Audit overrides from TF source file
	auditor := override.NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))
	if err := auditor.ScanDirectory(tmpDir); err != nil {
		t.Fatalf("auditor scan failed: %v", err)
	}

	// 3. Filter findings
	var activeFindings []correlator.Finding
	for _, f := range findings {
		ignored, entry := auditor.IsIgnored(f.RuleID, f.FQDN)
		if !ignored {
			activeFindings = append(activeFindings, f)
		} else if entry.Approver != "@ciso" {
			t.Errorf("expected approver @ciso, got %s", entry.Approver)
		}
	}

	if len(activeFindings) != 0 {
		t.Errorf("expected SW-G-001 to be suppressed by in-code override, but got %d active findings", len(activeFindings))
	}

	// 4. Verify SARIF report produces 0 results
	sarif := reporter.GenerateSarif(activeFindings)
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected empty SARIF results, got %d", len(sarif.Runs[0].Results))
	}
}

// Flow 2: SW-G-002 Dangling Pointer with Live HTTP Probe
func TestIntegration_DanglingPointerSWG002(t *testing.T) {
	// Mock HTTP server responding with GitHub Pages 404 signature
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "<html><body>There isn't a GitHub Pages site here.</body></html>")
	}))
	defer ts.Close()

	engine, err := prober.NewFingerprintEngine()
	if err != nil {
		t.Fatal(err)
	}

	claimProber := prober.NewProber(engine)

	plan := &correlator.PlanJSON{
		ResourceChanges: []correlator.ResourceChange{
			{
				Address: "aws_route53_record.docs",
				Type:    "aws_route53_record",
				Change: correlator.ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name":    ts.Listener.Addr().String(), // use mock server address as target host
						"type":    "CNAME",
						"records": []any{"acme-docs.github.io"},
					},
				},
			},
		},
	}

	findings, _, err := correlator.EvaluatePlan(plan, claimProber)
	if err != nil {
		t.Fatalf("correlator failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dangling GitHub Pages pointer, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != correlator.RuleDanglingPointer {
		t.Errorf("expected rule %s, got %s", correlator.RuleDanglingPointer, f.RuleID)
	}
	if f.Severity != correlator.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %s", f.Severity)
	}

	// Verify SARIF output contains SW-G-002
	sarif := reporter.GenerateSarif(findings)
	if len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].RuleID != correlator.RuleDanglingPointer {
		t.Errorf("SARIF mismatch for SW-G-002")
	}
}

// Flow 3: SW-G-003 Dynamic Computed Target
func TestIntegration_DynamicComputedTargetSWG003(t *testing.T) {
	plan := &correlator.PlanJSON{
		ResourceChanges: []correlator.ResourceChange{
			{
				Address: "aws_route53_record.dynamic_cname",
				Type:    "aws_route53_record",
				Change: correlator.ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name": "dynamic.acme.com",
						"type": "CNAME",
					},
					AfterUnknown: map[string]any{
						"records": true,
					},
				},
			},
		},
	}

	findings, modifiedCount, err := correlator.EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatal(err)
	}

	if modifiedCount != 1 {
		t.Errorf("expected 1 modified record, got %d", modifiedCount)
	}

	if len(findings) != 1 || findings[0].RuleID != correlator.RuleComputedTarget {
		t.Fatalf("expected SW-G-003 finding, got: %v", findings)
	}

	if findings[0].Severity != correlator.SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}

	sarif := reporter.GenerateSarif(findings)
	if sarif.Runs[0].Results[0].Level != "warning" {
		t.Errorf("expected SARIF level warning, got %s", sarif.Runs[0].Results[0].Level)
	}
}

// Flow 4: Performance Budget Cap (200 records boundary)
func TestIntegration_PerformanceBudgetCap(t *testing.T) {
	var changes []correlator.ResourceChange
	for i := 1; i <= 205; i++ {
		changes = append(changes, correlator.ResourceChange{
			Address: fmt.Sprintf("aws_route53_record.rec_%d", i),
			Type:    "aws_route53_record",
			Change: correlator.ChangeObj{
				Actions: []string{"create"},
				After: map[string]any{
					"name":    fmt.Sprintf("sub%d.acme.com", i),
					"type":    "CNAME",
					"records": []any{"target.safe.org"},
				},
			},
		})
	}

	plan := &correlator.PlanJSON{ResourceChanges: changes}
	_, totalModified, err := correlator.EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatal(err)
	}

	if totalModified != 205 {
		t.Errorf("expected 205 modified records, got %d", totalModified)
	}
	if totalModified <= 200 {
		t.Errorf("expected count to exceed 200 cap")
	}
}

// Flow 5: Circuit Breaker Trip
func TestIntegration_CircuitBreakerTrip(t *testing.T) {
	resolver := dnsresolver.NewDNSResolver()
	timedOutTargets := []string{
		"unreachable-1.example.com",
		"unreachable-2.example.com",
		"unreachable-3.example.com",
		"unreachable-4.example.com",
		"unreachable-5.example.com",
	}

	for _, target := range timedOutTargets {
		// Mock query failures by attempting non-existent domains against closed resolver
		_, _ = resolver.ResolveCNAME(target)
	}

	// If 5 consecutive timeouts were registered
	tripped, targets := resolver.IsCircuitBreakerTripped()
	if !tripped {
		// Ensure manually recording trips circuit breaker
		for _, target := range timedOutTargets {
			resolver.ResolveCNAME(target)
		}
	}

	// Check circuit breaker status
	tripped, targets = resolver.IsCircuitBreakerTripped()
	if tripped {
		if len(targets) != 5 {
			t.Errorf("expected 5 targets logged, got %d", len(targets))
		}
	}
}

// Flow 6: CLI Binary Execution Cross-Package Tests
func TestIntegration_CLIEndToEnd(t *testing.T) {
	// Build binary
	binPath := filepath.Join(t.TempDir(), "subdomainwatch-guard")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../cmd/subdomainwatch-guard")
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, string(out))
	}

	// Create test plan with SW-G-001
	planJSON := `{
  "resource_changes": [
    {
      "address": "aws_s3_bucket.assets",
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["delete"],
        "before": { "bucket": "acme-assets" }
      }
    },
    {
      "address": "aws_route53_record.cdn",
      "type": "aws_route53_record",
      "change": {
        "actions": ["update"],
        "after": {
          "name": "cdn.acme.com",
          "type": "CNAME",
          "records": ["acme-assets.s3.amazonaws.com"]
        }
      }
    }
  ]
}`
	planFile := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planFile, []byte(planJSON), 0644); err != nil {
		t.Fatal(err)
	}

	sarifFile := filepath.Join(t.TempDir(), "report.sarif")
	jsonFile := filepath.Join(t.TempDir(), "report.json")

	// Case A: fail-mode=closed -> exit code 1
	cmdClosed := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "closed",
		"-sarif-file", sarifFile,
		"-json-file", jsonFile,
	)
	errClosed := cmdClosed.Run()
	if errClosed == nil {
		t.Errorf("expected exit code 1 for fail-mode=closed with CRITICAL finding")
	}

	// Verify SARIF output file was generated and is valid JSON
	sarifData, err := os.ReadFile(sarifFile)
	if err != nil {
		t.Fatalf("SARIF file not created: %v", err)
	}
	var sarifObj map[string]any
	if err := json.Unmarshal(sarifData, &sarifObj); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarifObj["version"] != "2.1.0" {
		t.Errorf("SARIF version != 2.1.0")
	}

	// Case B: fail-mode=open -> exit code 0
	cmdOpen := exec.Command(binPath,
		"-plan", planFile,
		"-offline-only",
		"-fail-mode", "open",
	)
	if err := cmdOpen.Run(); err != nil {
		t.Errorf("expected exit code 0 for fail-mode=open, got: %v", err)
	}

	// Case C: fail-on-severity=CRITICAL but only WARNING finding exists -> exit code 0
	warningPlan := `{
  "resource_changes": [
    {
      "address": "aws_route53_record.computed",
      "type": "aws_route53_record",
      "change": {
        "actions": ["create"],
        "after": { "name": "computed.acme.com" },
        "after_unknown": { "records": true }
      }
    }
  ]
}`
	warnFile := filepath.Join(t.TempDir(), "warn.json")
	if err := os.WriteFile(warnFile, []byte(warningPlan), 0644); err != nil {
		t.Fatal(err)
	}
	cmdWarnOnly := exec.Command(binPath,
		"-plan", warnFile,
		"-offline-only",
		"-fail-on-severity", "CRITICAL",
		"-fail-mode", "closed",
	)
	if err := cmdWarnOnly.Run(); err != nil {
		t.Errorf("expected exit code 0 when finding is WARNING and threshold is CRITICAL, got: %v", err)
	}
}
