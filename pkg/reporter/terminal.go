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
	fmt.Fprintf(w, "%s║           SUBDOMAINWATCH TAKEOVER GUARD v2.1.0 (HARDENED)             ║%s\n", colorCyan, colorReset)
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
		fmt.Fprintf(w, "    %sReason:%s %s\n\n", colorDim, colorReset, f.Reason)
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
