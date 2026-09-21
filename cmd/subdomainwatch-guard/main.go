package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
	"github.com/subdomainwatch/takeover-guard/pkg/localscan"
	"github.com/subdomainwatch/takeover-guard/pkg/override"
	"github.com/subdomainwatch/takeover-guard/pkg/prober"
	"github.com/subdomainwatch/takeover-guard/pkg/reporter"
)

func main() {
	var (
		planFile        string
		mode            string
		failOnSeverity  string
		failMode        string
		sarifFile       string
		jsonFile        string
		tfDir           string
		settleDelay     int
		offlineOnly     bool
		signaturesURL   string
		localMode       bool
	)

	flag.StringVar(&planFile, "plan", "tfplan.json", "Path to terraform plan JSON")
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
	flag.Parse()

	// Environment variable overrides (from GitHub Actions env)
	if envKey := os.Getenv("SUBDOMAINWATCH_API_KEY"); envKey == "" {
		fmt.Fprintf(os.Stderr, "ℹ No SUBDOMAINWATCH_API_KEY detected. Running in Standalone Local Engine Mode (zero secrets exfiltration risk).\n")
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
			fmt.Fprintln(os.Stderr, "Error: Timeout reached during settle delay")
			os.Exit(1)
		}
	}

	// 2. Initialize Fingerprint Engine & Prober (§5)
	engine, err := prober.NewFingerprintEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing fingerprint engine: %v\n", err)
		if strings.EqualFold(failMode, "closed") {
			os.Exit(1)
		}
		os.Exit(0)
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
		localRes, err := localscan.RunLocalEngine(ctx, tfDir, claimProber)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during local scan: %v\n", err)
			if strings.EqualFold(failMode, "closed") {
				os.Exit(1)
			}
			os.Exit(0)
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
			fmt.Fprintf(os.Stderr, "Error: Failed to read plan file '%s': %v\n", planFile, err)
			if strings.EqualFold(failMode, "closed") {
				os.Exit(1)
			}
			os.Exit(0)
		}

		findings, modifiedCount, err := correlator.EvaluatePlanBytes(planBytes, claimProber)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error evaluating plan: %v\n", err)
			if strings.EqualFold(failMode, "closed") {
				os.Exit(1)
			}
			os.Exit(0)
		}
		totalModified = modifiedCount

		// Check Performance Budget Cap: 200 records (§7)
		const maxRecords = 200
		if totalModified > maxRecords {
			reporter.PrintBudgetExceeded(os.Stderr, totalModified, maxRecords)
			if strings.EqualFold(failMode, "closed") {
				os.Exit(1)
			}
		}

		// Audit In-Code Overrides (§9)
		auditor := override.NewOverrideAuditor()
		if err := auditor.ScanDirectory(tfDir); err != nil {
			fmt.Fprintf(os.Stderr, "❌ In-Code Override Validation Failure: %v\n", err)
			os.Exit(1)
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
