package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

// Terminal ANSI colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[1;31m"
	colorGreen  = "\033[1;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[1;36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func PrintBanner(w io.Writer, mode string) {
	fmt.Fprintf(w, "\n%s╔═══════════════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, "%s║           SUBDOMAINWATCH TAKEOVER GUARD v2.2.0 (HARDENED)             ║%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, "%s║  Shift-Left IaC Security Gate & Mandatory Post-Apply Sentinel Engine  ║%s\n", colorDim, colorReset)
	fmt.Fprintf(w, "%s╚═══════════════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, " %sMode:%s %s\n\n", colorBold, colorReset, mode)
}

func PrintResults(w io.Writer, report *SummaryReport) {
	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "%s✔ NO SUBDOMAIN TAKEOVER RISKS DETECTED%s\n", colorGreen, colorReset)
		fmt.Fprintf(w, "  Analyzed %d modified DNS records across plan changes. All targets verified safe.\n\n", report.TotalModifiedRecords)
		return
	}

	fmt.Fprintf(w, "%s⚠ SECURITY GATE FINDINGS DETECTED (%d total)%s\n", colorRed, len(report.Findings), colorReset)
	fmt.Fprintf(w, "  Critical: %d | High: %d | Warning: %d\n\n", report.CriticalCount, report.HighCount, report.WarningCount)

	for i, f := range report.Findings {
		var badgeColor string
		switch f.Severity {
		case correlator.SeverityCritical:
			badgeColor = colorRed
		case correlator.SeverityHigh:
			badgeColor = colorYellow
		default:
			badgeColor = colorCyan
		}

		fmt.Fprintf(w, " %d. %s[%s]%s %s%s%s (Rule: %s)\n", i+1, badgeColor, f.Severity, colorReset, colorBold, f.FQDN, colorReset, f.RuleID)
		if f.Target != "" {
			fmt.Fprintf(w, "    %sTarget:%s %s\n", colorDim, colorReset, f.Target)
		}
		if f.Address != "" {
			fmt.Fprintf(w, "    %sResource:%s %s\n", colorDim, colorReset, f.Address)
		}
		// Clickable file:line so CI terminals and editors jump to the exact
		// Terraform/HCL record that produced the finding (HCL dir scans only;
		// plan-JSON mode has no source locations to map).
		if f.SourceFile != "" {
			loc := f.SourceFile
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.SourceFile, f.StartLine)
			}
			fmt.Fprintf(w, "    %sLocation:%s %s\n", colorCyan, colorReset, loc)
		}
		fmt.Fprintf(w, "    %sReason:%s %s\n", colorDim, colorReset, f.Reason)
		fmt.Fprintf(w, "    %sImpact:%s %s\n\n", colorDim, colorReset, plainBlastRadius(f))
	}

	fmt.Fprintf(w, "%sNEXT STEPS:%s delete or re-point the listed DNS records (or claim the target\n", colorBold, colorReset)
	fmt.Fprintf(w, "cloud resource), then re-run the scan. Use --sarif results.sarif to publish\n")
	fmt.Fprintf(w, "file:line annotations to GitHub code scanning.\n\n")
}

// plainBlastRadius renders a one-line, jargon-free consequence statement so
// CI logs explain *why* a dangling record matters (phishing, cookie theft,
// malware hosting) without requiring DNS expertise.
func plainBlastRadius(f correlator.Finding) string {
	switch f.Severity {
	case correlator.SeverityCritical:
		return "Unclaimed cloud resource behind this hostname - attackers can host fake login pages, steal session cookies, and serve malware on your domain."
	case correlator.SeverityHigh:
		return "Likely takeover path on this hostname - credential phishing and SSO redirect abuse become possible if the target stays unclaimed."
	default:
		return "Target is unresolvable at plan time - verify after apply, otherwise the record may resolve to an unclaimed service."
	}
}

func PrintCircuitBreakerTrip(w io.Writer, timedOutTargets []string) {
	fmt.Fprintf(w, "\n%s🚨 CIRCUIT_BREAKER_TRIP: SECURITY GATE ABORTED%s\n", colorRed, colorReset)
	fmt.Fprintf(w, "5 consecutive DNS timeouts detected on targets:\n")
	for i, target := range timedOutTargets {
		fmt.Fprintf(w, "  %d. %s\n", i+1, target)
	}
	fmt.Fprintf(w, "\n%sHard build failure enforced. Manual security review required.%s\n\n", colorBold, colorReset)
}

func PrintBudgetExceeded(w io.Writer, count, max int) {
	fmt.Fprintf(w, "\n%s🚨 SECURITY GATE BUDGET EXCEEDED%s\n", colorRed, colorReset)
	fmt.Fprintf(w, "Plan contains %s%d%s modified DNS records, exceeding the %d performance budget cap.\n", colorBold, count, colorReset, max)
	fmt.Fprintf(w, "To maintain fast CI SLA, scope execution with path filtering: %spaths: [\"terraform/dns/**\"]%s\n\n", strings.TrimSpace(colorCyan), colorReset)
}

func PrintSnippets(w io.Writer, snippets map[string]string) {
	if len(snippets) == 0 {
		return
	}
	fmt.Fprintf(w, "%s💡 PRE-COMMIT OVERRIDE ASSISTANT:%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, "  If an accepted business risk exists, paste the comment directly above the resource block (line N-1):\n\n")
	for fqdn, snippet := range snippets {
		fmt.Fprintf(w, "  %s%s:%s\n", colorBold, fqdn, colorReset)
		fmt.Fprintf(w, "    %s%s%s\n\n", colorYellow, snippet, colorReset)
	}
}
