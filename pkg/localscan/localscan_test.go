package localscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	res, err := RunLocalEngine(context.Background(), LocalScanOptions{
		WorkspaceDir: tmpDir,
		Prober:       prober,
	})
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

	res, err := RunLocalEngine(context.Background(), LocalScanOptions{
		WorkspaceDir: tmpDir,
		Prober:       prober,
	})
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

func TestLocalScanWithPlanJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-plan-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	planJSON := `{
  "resource_changes": [
    {
      "address": "aws_route53_record.from_plan",
      "type": "aws_route53_record",
      "change": {
        "actions": ["create"],
        "after": {
          "name": "plan.acme.com",
          "type": "CNAME",
          "records": ["unmanaged-bucket.s3.amazonaws.com"]
        }
      }
    }
  ]
}`
	planPath := filepath.Join(tmpDir, "speculative.json")
	if err := os.WriteFile(planPath, []byte(planJSON), 0644); err != nil {
		t.Fatal(err)
	}

	prober := &mockLocalProber{
		isCloud: true,
		isVuln:  true,
	}

	res, err := RunLocalEngine(context.Background(), LocalScanOptions{
		WorkspaceDir: tmpDir,
		PlanJSONPath: planPath,
		Prober:       prober,
	})
	if err != nil {
		t.Fatalf("local engine failed: %v", err)
	}

	if !res.UsedPlan {
		t.Errorf("expected UsedPlan to be true")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from plan, got %d", len(res.Findings))
	}
	if res.Findings[0].FQDN != "plan.acme.com" {
		t.Errorf("expected plan.acme.com, got %s", res.Findings[0].FQDN)
	}
}

func TestLocalScanWithOverrideFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guard-override-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Valid in-code ignore comment preceding dangling record
	tfContent := `# subdomainwatch-ignore: SW-G-002 domain=ignored.acme.com expires=2026-11-01 approver=@security reason="Accepted test risk"
resource "aws_route53_record" "ignored_record" {
  name    = "ignored.acme.com"
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

	res, err := RunLocalEngine(context.Background(), LocalScanOptions{
		WorkspaceDir: tmpDir,
		Prober:       prober,
	})
	if err != nil {
		t.Fatalf("local engine failed: %v", err)
	}

	// EvaluatedRecords should still count 1 record
	if res.EvaluatedRecords != 1 {
		t.Errorf("expected 1 evaluated record, got %d", res.EvaluatedRecords)
	}

	// Finding should be filtered out by override
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 active findings due to override suppression, got %d", len(res.Findings))
	}
}
