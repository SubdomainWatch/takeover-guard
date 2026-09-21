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
