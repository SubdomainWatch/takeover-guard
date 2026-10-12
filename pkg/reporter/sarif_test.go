package reporter

import (
	"encoding/json"
	"testing"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

func TestGenerateSarif(t *testing.T) {
	findings := []correlator.Finding{
		{
			RuleID:     correlator.RuleUncoordinatedOrphan,
			Severity:   correlator.SeverityCritical,
			FQDN:       "staging.acme.com",
			Target:     "acme-staging.s3.amazonaws.com",
			Address:    "aws_route53_record.staging",
			SourceFile: "terraform/dns.tf",
			StartLine:  42,
			Reason:     "Underlying s3 resource 'acme-staging' is deleted in this plan, but DNS record 'staging.acme.com' remains active.",
		},
	}

	report := GenerateSarif(findings)
	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", report.Version)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "SubdomainWatch Takeover Guard" {
		t.Errorf("expected tool name 'SubdomainWatch Takeover Guard', got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != correlator.RuleUncoordinatedOrphan {
		t.Errorf("expected rule ID %s, got %s", correlator.RuleUncoordinatedOrphan, res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level error, got %s", res.Level)
	}

	// Verify serialization to valid JSON
	bytes, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal SARIF JSON: %v", err)
	}

	if len(bytes) == 0 {
		t.Errorf("empty SARIF JSON output")
	}
}
