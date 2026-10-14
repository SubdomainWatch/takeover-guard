package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
	"github.com/subdomainwatch/takeover-guard/pkg/localscan"
	"github.com/subdomainwatch/takeover-guard/pkg/override"
	"github.com/subdomainwatch/takeover-guard/pkg/prober"
	"github.com/subdomainwatch/takeover-guard/pkg/reporter"
	"github.com/subdomainwatch/takeover-guard/pkg/syncer"
)

func main() {
	var (
		planFile       string
		mode           string
		failOnSeverity string
		failMode       string
		sarifFile      string
		jsonFile       string
		tfDir          string
		settleDelay    int
		offlineOnly    bool
		signaturesURL  string
		localMode      bool
		syncURL        string
	)

	flag.StringVar(&planFile, "plan-file", "tfplan.json", "Path to terraform plan JSON")
	flag.StringVar(&planFile, "plan", "tfplan.json", "Path to terraform plan JSON (alias for -plan-file)")
	flag.StringVar(&mode, "mode", "pre-merge", "Execution mode: pre-merge, post-apply-sentinel, or pre-commit")
	flag.StringVar(&failOnSeverity, "fail-on-severity", "CRITICAL", "Minimum severity to fail build: CRITICAL, HIGH, WARNING")
	flag.StringVar(&failMode, "fail-mode", "closed", "Behavior on failure: closed (fail build) or open (warn only)")
	flag.StringVar(&sarifFile, "sarif-file", "subdomainwatch-guard.sarif", "Destination path for SARIF 2.1.0 report")
	flag.StringVar(&jsonFile, "json-file", "", "Optional destination path for JSON summary report")
	flag.StringVar(&tfDir, "tf-dir", ".", "Directory containing Terraform HCL files to inspect for in-code overrides or local scan")
	flag.IntVar(&settleDelay, "settle-delay", 45, "Settle delay in seconds for DNS propagation in post-apply mode")
	flag.BoolVar(&offlineOnly, "offline-only", false, "Force offline embedded signatures bundle")
	flag.StringVar(&signaturesURL, "signatures-url", "", "Custom remote URL for verified signatures")
	flag.BoolVar(&localMode, "local", false, "Run local developer pre-commit engine across .tf files")
	flag.StringVar(&syncURL, "sync-url", "", "SubdomainWatch SaaS sync endpoint (default: https://subdomainwatch.com/api/guard/sync)")
	flag.Parse()

	// Environment variable overrides (from GitHub Actions env)
	if failMode != "closed" && failMode != "open" {
		exitConfigFail(failMode, "ERROR: Invalid fail mode %q; expected closed or open.\n", failMode)
	}
	if envKey := os.Getenv("SUBDOMAINWATCH_API_KEY"); envKey == "" {
		fmt.Fprintf(os.Stderr, "ℹ No SUBDOMAINWATCH_API_KEY detected. Running in Standalone Local Engine Mode (zero secrets exfiltration risk).\n")
	} else if !regexp.MustCompile(`^sw_guard_[0-9a-f]{48}$`).MatchString(envKey) {
		exitConfigFail(failMode, "ERROR: Invalid SUBDOMAINWATCH_API_KEY format. Expected sw_guard_<48-hex>.\n")
	}

	// 1. Global Performance Budget & Hard Timeout Cap (§7)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	reporter.PrintBanner(os.Stdout, mode)

	// In Post-Apply Sentinel mode, optionally execute settle delay (§2.3, §3.3)
	if mode == "post-apply-sentinel" && settleDelay > 0 {
		fmt.Printf("⏳ Awaiting DNS propagation settle delay (%d seconds)...\n", settleDelay)
		select {
		case <-time.After(time.Duration(settleDelay) * time.Second):
		case <-ctx.Done():
			exitConfigFail(failMode, "Error: Timeout reached during settle delay\n")
		}
	}

	// 2. Initialize Fingerprint Engine & Prober (§5)
	engine, err := prober.NewFingerprintEngine()
	if err != nil {
		exitConfigFail(failMode, "Error initializing fingerprint engine: %v\n", err)
	}

	if !offlineOnly {
		if err := engine.UpdateFromRemote(signaturesURL); err != nil {
			fmt.Printf("ℹ Using embedded offline signature bundle (version %s)\n", engine.Bundle.Version)
		} else {
			fmt.Printf("✔ Updated to remote signatures (version %s)\n", engine.Bundle.Version)
		}
	} else {
		fmt.Printf("ℹ Air-gapped offline mode: using embedded bundle (version %s)\n", engine.Bundle.Version)
	}

	claimProber := prober.NewProber(engine)

	var activeFindings []correlator.Finding
	var totalModified int
	var overrideSnippets map[string]string

	// 3. Execution Path: Local Engine vs CI Plan Ingestion
	planFileExists := fileExists(planFile)
	if localMode || (!planFileExists && isTFDir(tfDir)) {
		fmt.Printf("🔍 Running Local Developer Pre-Commit Engine in '%s'...\n", tfDir)
		var planPath string
		if planFileExists {
			planPath = planFile
		}
		localRes, err := localscan.RunLocalEngine(ctx, localscan.LocalScanOptions{
			WorkspaceDir: tfDir,
			PlanJSONPath: planPath,
			Prober:       claimProber,
		})
		if err != nil {
			exitConfigFail(failMode, "Error during local scan: %v\n", err)
		}

		activeFindings = localRes.Findings
		totalModified = localRes.EvaluatedRecords
		overrideSnippets = localRes.OverrideSnippets

		if localRes.UsedPlan {
			fmt.Println("✔ Analyzed local speculative plan.")
		} else {
			fmt.Printf("✔ Scanned %d Terraform resources across local .tf files.\n", localRes.EvaluatedRecords)
		}
	} else {
		// CI Plan Path
		planBytes, err := os.ReadFile(planFile)
		if err != nil {
			exitConfigFail(failMode, "Error: Failed to read plan file '%s': %v\n", planFile, err)
		}

		findings, modifiedCount, err := correlator.EvaluatePlanBytes(planBytes, claimProber)
		if err != nil {
			exitConfigFail(failMode, "Error evaluating plan: %v\n", err)
		}
		totalModified = modifiedCount

		// Check Performance Budget Cap: 200 records (§7)
		const maxRecords = 200
		if totalModified > maxRecords {
			reporter.PrintBudgetExceeded(os.Stderr, totalModified, maxRecords)
			exitConfigFail(failMode, "Execution budget exceeded; refusing to continue.\n")
		}

		// Audit In-Code Overrides (§9)
		auditor := override.NewOverrideAuditor()
		if err := auditor.ScanDirectory(tfDir); err != nil {
			exitConfigFail(failMode, "❌ In-Code Override Validation Failure: %v\n", err)
		}

		for _, f := range findings {
			ignored, entry := auditor.IsIgnored(f.RuleID, f.FQDN)
			if ignored && entry != nil {
				fmt.Printf("ℹ Override applied for %s (%s) approved by %s until %s (Reason: %s)\n",
					f.FQDN, f.RuleID, entry.Approver, entry.Expires.Format("2006-01-02"), entry.Reason)
			} else {
				activeFindings = append(activeFindings, f)
			}
		}
	}

	// 4. Generate SARIF 2.1.0 & JSON Reports (§8)
	if sarifFile != "" {
		if err := reporter.WriteSarifFile(sarifFile, activeFindings); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to write SARIF report: %v\n", err)
		} else {
			fmt.Printf("✔ SARIF 2.1.0 report generated: %s\n", sarifFile)
		}
	}

	summary := reporter.GenerateSummaryReport(mode, totalModified, activeFindings)
	if jsonFile != "" {
		if err := reporter.WriteJSONFile(jsonFile, summary); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to write JSON report: %v\n", err)
		}
	}
	writeGitHubOutputs(sarifFile, len(activeFindings))

	// 5. Output Terminal Summary & Pre-Commit Overrides
	reporter.PrintResults(os.Stdout, summary)
	if len(overrideSnippets) > 0 {
		reporter.PrintSnippets(os.Stdout, overrideSnippets)
	}

	// 6. Determine Exit Code
	shouldFail := false
	minSeverity := strings.ToUpper(failOnSeverity)

	for _, f := range activeFindings {
		switch minSeverity {
		case "WARNING":
			shouldFail = true
		case "HIGH":
			if f.Severity == correlator.SeverityHigh || f.Severity == correlator.SeverityCritical {
				shouldFail = true
			}
		case "CRITICAL":
			if f.Severity == correlator.SeverityCritical {
				shouldFail = true
			}
		default:
			if f.Severity == correlator.SeverityCritical {
				shouldFail = true
			}
		}
		if shouldFail {
			break
		}
	}

	// 7. Sync Telemetry to SubdomainWatch SaaS (§10 Phase 3)
	apiKey := os.Getenv("SUBDOMAINWATCH_API_KEY")
	if apiKey != "" {
		envInfo := syncer.DetectEnvironment()
		status := "passed"
		if shouldFail {
			status = "failed"
		} else if len(activeFindings) > 0 {
			status = "warned"
		}

		var overrideList []syncer.OverridePayload
		for domain, snippet := range overrideSnippets {
			overrideList = append(overrideList, syncer.OverridePayload{
				Domain: domain,
				Reason: snippet,
			})
		}

		syncPayload := &syncer.SyncPayload{
			Repository:           envInfo.Repository,
			Branch:               envInfo.Branch,
			CommitSHA:            envInfo.CommitSHA,
			PRNumber:             envInfo.PRNumber,
			Mode:                 mode,
			ToolVersion:          "2.2.0",
			Timestamp:            time.Now().UTC().Format(time.RFC3339),
			Status:               status,
			TotalModifiedRecords: totalModified,
			CriticalCount:        summary.CriticalCount,
			HighCount:            summary.HighCount,
			WarningCount:         summary.WarningCount,
			Findings:             activeFindings,
			Overrides:            overrideList,
		}

		_ = syncer.SyncTelemetry(ctx, syncURL, apiKey, syncPayload)
	}

	if shouldFail {
		if strings.EqualFold(failMode, "closed") {
			fmt.Fprintf(os.Stderr, "❌ Security Gate Check FAILED: Issues found meeting or exceeding %s severity.\n", minSeverity)
			os.Exit(1)
		} else {
			fmt.Fprintf(os.Stderr, "⚠ Security Gate Check Warning: Issues found meeting or exceeding %s severity (fail-mode: open).\n", minSeverity)
			os.Exit(0)
		}
	}

	os.Exit(0)
}

// exitConfigFail reports operational/configuration failures separately from blocking findings.
func exitConfigFail(_ string, format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(2)
}

// writeGitHubOutputs publishes declared GitHub Action outputs when available.
func writeGitHubOutputs(sarifFile string, findingsCount int) {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return
	}
	if strings.ContainsAny(sarifFile, "\r\n") {
		exitConfigFail("closed", "Invalid SARIF output path for GITHUB_OUTPUT\n")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		exitConfigFail("closed", "Failed to open GITHUB_OUTPUT: %v\n", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "sarif_file=%s\nfindings_count=%d\n", sarifFile, findingsCount); err != nil {
		exitConfigFail("closed", "Failed to write GITHUB_OUTPUT: %v\n", err)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func isTFDir(dir string) bool {
	hasTF := false
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tf") {
			hasTF = true
			return filepath.SkipAll
		}
		return nil
	})
	return hasTF
}
