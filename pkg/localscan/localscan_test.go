package localscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

type mockLocalProber struct {
	isCloud bool
	isVuln  bool
}

func (m *mockLocalProber) IsCloudProviderTarget(target string) bool {
	return m.isCloud
}

func (m *mockLocalProber) ProbeClaimability(fqdn, target string) (bool, string, string) {
	return m.isVuln, "CRITICAL", "Delete dangling record"
}

func TestStaticHCLScanning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-local-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tfContent := `
resource "aws_s3_bucket" "active_bucket" {
  bucket = "my-active-local-bucket"
}

resource "aws_route53_record" "safe_record" {
  name    = "safe.acme.com"
  type    = "CNAME"
  records = ["my-active-local-bucket.s3.amazonaws.com"]
}

resource "aws_route53_record" "dangling_record" {
  name    = "dangling.acme.com"
  type    = "CNAME"
  records = ["unmanaged-bucket.s3.amazonaws.com"]
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(tfContent), 0644); err != nil {
		t.Fatal(err)
	}

	prober := &mockLocalProber{
		isCloud: true,
		isVuln:  true,
	}

	res, err := RunLocalEngine(context.Background(), tmpDir, prober)
	if err != nil {
		t.Fatalf("local engine failed: %v", err)
	}

	if res.EvaluatedRecords != 2 {
		t.Errorf("expected 2 evaluated records, got %d", res.EvaluatedRecords)
	}

	// safe_record points to my-active-local-bucket which exists locally, so not flagged
	// dangling_record points to unmanaged-bucket which does not exist locally and is claimable
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for unmanaged dangling bucket, got %d", len(res.Findings))
	}

	f := res.Findings[0]
	if f.FQDN != "dangling.acme.com" {
		t.Errorf("expected dangling.acme.com, got %s", f.FQDN)
	}

	// Verify suggested snippet
	snippet, ok := res.OverrideSnippets[f.FQDN]
	if !ok {
		t.Errorf("missing suggested snippet for %s", f.FQDN)
	}
	if !strings.Contains(snippet, "# subdomainwatch-ignore:") || !strings.Contains(snippet, "domain=dangling.acme.com") {
		t.Errorf("invalid snippet content: %s", snippet)
	}
}

func TestMultiLineRecordsArrayAndAliasBlock(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-multiline-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Tests multi-line records with terraform fmt indentation and trailing commas,
	// plus an alias block where name is inside alias {} without conflicting with record name.
	tfContent := `
resource "aws_route53_record" "multiline_record" {
  name = "multiline.acme.com"
  type = "CNAME"
  records = [
    "unmanaged-multiline.s3.amazonaws.com",
  ]
}

resource "aws_route53_record" "alias_record" {
  name = "alias.acme.com"
  type = "A"
  alias {
    name                   = "unmanaged-alias.s3-website-us-east-1.amazonaws.com"
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = false
  }
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "dns.tf"), []byte(tfContent), 0644); err != nil {
		t.Fatal(err)
	}

	prober := &mockLocalProber{
		isCloud: true,
		isVuln:  true,
	}

	res, err := RunLocalEngine(context.Background(), tmpDir, prober)
	if err != nil {
		t.Fatalf("local engine failed: %v", err)
	}

	if res.EvaluatedRecords != 2 {
		t.Fatalf("expected 2 evaluated records, got %d", res.EvaluatedRecords)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings (multiline records + alias block), got %d", len(res.Findings))
	}

	foundMultiline := false
	foundAlias := false
	for _, f := range res.Findings {
		if f.FQDN == "multiline.acme.com" && f.Target == "unmanaged-multiline.s3.amazonaws.com" {
			foundMultiline = true
		}
		if f.FQDN == "alias.acme.com" && f.Target == "unmanaged-alias.s3-website-us-east-1.amazonaws.com" {
			foundAlias = true
		}
	}

	if !foundMultiline {
		t.Errorf("expected finding for multiline.acme.com with target unmanaged-multiline.s3.amazonaws.com")
	}
	if !foundAlias {
		t.Errorf("expected finding for alias.acme.com with target unmanaged-alias.s3-website-us-east-1.amazonaws.com")
	}
}

func TestRunLocalEngine_SupportedProviders(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-providers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tfContent := `
resource "aws_route53_record" "aws_rec" {
  name    = "aws.example.com"
  type    = "CNAME"
  records = ["unmanaged-aws.s3.amazonaws.com"]
}

resource "cloudflare_record" "cf_rec" {
  name    = "cf.example.com"
  type    = "CNAME"
  content = "unmanaged-cf.s3.amazonaws.com"
}

resource "azurerm_dns_cname_record" "azure_rec" {
  name                = "azure"
  zone_name           = "example.com"
  record              = "unmanaged-azure.azurewebsites.net"
  resource_group_name = "rg-dns"
}

resource "google_dns_record_set" "gcp_rec" {
  name         = "gcp.example.com."
  type         = "CNAME"
  managed_zone = "zone-example"
  rrdatas      = ["unmanaged-gcp.storage.googleapis.com"]
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "providers.tf"), []byte(tfContent), 0644); err != nil {
		t.Fatal(err)
	}

	prober := &mockLocalProber{
		isCloud: true,
		isVuln:  true,
	}

	res, err := RunLocalEngine(context.Background(), tmpDir, prober)
	if err != nil {
		t.Fatalf("local engine failed: %v", err)
	}

	if res.EvaluatedRecords != 4 {
		t.Fatalf("expected 4 evaluated records across supported providers, got %d", res.EvaluatedRecords)
	}

	if len(res.Findings) != 4 {
		t.Fatalf("expected 4 findings across all supported providers, got %d", len(res.Findings))
	}

	expectedDomains := map[string]bool{
		"aws.example.com":   false,
		"cf.example.com":    false,
		"azure.example.com": false,
		"gcp.example.com":   false,
	}

	for _, f := range res.Findings {
		if _, ok := expectedDomains[f.FQDN]; ok {
			expectedDomains[f.FQDN] = true
		}
	}

	for dom, found := range expectedDomains {
		if !found {
			t.Errorf("expected finding for provider domain %s", dom)
		}
	}
}

func TestRunLocalEngine_PlanJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-plan-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	planJSON := `{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.orphan_bucket",
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["delete"],
        "before": {
          "bucket": "acme-orphan-bucket"
        }
      }
    },
    {
      "address": "aws_route53_record.dangling",
      "type": "aws_route53_record",
      "change": {
        "actions": ["no-op"],
        "after": {
          "name": "orphan.acme.com",
          "type": "CNAME",
          "records": [
            "acme-orphan-bucket.s3.amazonaws.com"
          ]
        }
      }
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "tfplan.json"), []byte(planJSON), 0644); err != nil {
		t.Fatal(err)
	}

	prober := &mockLocalProber{
		isCloud: true,
		isVuln:  true,
	}

	res, err := RunLocalEngine(context.Background(), tmpDir, prober)
	if err != nil {
		t.Fatalf("local engine failed on tfplan.json: %v", err)
	}

	if !res.UsedPlan {
		t.Errorf("expected UsedPlan to be true when tfplan.json exists")
	}

	if res.EvaluatedRecords != 1 {
		t.Errorf("expected 1 evaluated record from plan, got %d", res.EvaluatedRecords)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from plan, got %d", len(res.Findings))
	}

	if res.Findings[0].FQDN != "orphan.acme.com" {
		t.Errorf("expected finding FQDN orphan.acme.com, got %s", res.Findings[0].FQDN)
	}
}

func TestGenerateSnippets_Formatting(t *testing.T) {
	findings := []correlator.Finding{
		{
			RuleID: correlator.RuleDanglingPointer,
			FQDN:   "snippet.example.com",
		},
	}

	snippets := generateSnippets(findings)
	snippet, ok := snippets["snippet.example.com"]
	if !ok {
		t.Fatalf("expected snippet for snippet.example.com")
	}

	if !strings.HasPrefix(snippet, "# subdomainwatch-ignore: "+correlator.RuleDanglingPointer) {
		t.Errorf("expected snippet to start with '# subdomainwatch-ignore: %s', got %s", correlator.RuleDanglingPointer, snippet)
	}
	if !strings.Contains(snippet, "domain=snippet.example.com") {
		t.Errorf("expected snippet to contain 'domain=snippet.example.com', got %s", snippet)
	}
	if !strings.Contains(snippet, "expires=") {
		t.Errorf("expected snippet to contain 'expires=', got %s", snippet)
	}
	if !strings.Contains(snippet, "approver=@") {
		t.Errorf("expected snippet to contain 'approver=@', got %s", snippet)
	}
	if !strings.Contains(snippet, `reason="Accepted pre-commit risk"`) {
		t.Errorf("expected snippet to contain reason 'Accepted pre-commit risk', got %s", snippet)
	}
}
