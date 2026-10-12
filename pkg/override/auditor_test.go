package override

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidLineN1Override(t *testing.T) {
	content := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason="Accepted staging risk"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	if err := auditor.ScanFile(tmpFile.Name()); err != nil {
		t.Fatalf("expected valid scan, got: %v", err)
	}

	ignored, entry := auditor.IsIgnored("SW-G-001", "staging.acme.com")
	if !ignored {
		t.Errorf("expected finding to be ignored")
	}
	if entry == nil || entry.Approver != "@sec-ops" {
		t.Errorf("expected approver @sec-ops, got %v", entry)
	}
}

func TestOneBlankLineBetweenCommentAndResource(t *testing.T) {
	content := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason="Accepted staging risk"

resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	if err := auditor.ScanFile(tmpFile.Name()); err != nil {
		t.Fatalf("expected 1 blank line to be allowed, got error: %v", err)
	}
}

func TestDetachedCommentFails(t *testing.T) {
	content := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason="Accepted staging risk"


resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	err = auditor.ScanFile(tmpFile.Name())
	if err == nil || !strings.Contains(err.Error(), "Detached") {
		t.Errorf("expected error rejecting detached comment, got: %v", err)
	}
}

func TestExpiredCommentDoesNotCrashBuild(t *testing.T) {
	content := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-09-01 approver=@sec-ops reason="Past expiry"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	// P1-4 / Gap 3: Expired overrides should not crash the scanner with a hard error
	err = auditor.ScanFile(tmpFile.Name())
	if err != nil {
		t.Errorf("expected ScanFile to succeed with non-crash warning for expired override, got error: %v", err)
	}

	// Should not be ignored because it is expired
	ignored, _ := auditor.IsIgnored("SW-G-001", "staging.acme.com")
	if ignored {
		t.Errorf("expected expired override NOT to be ignored")
	}
}

func TestSlashSlashComment(t *testing.T) {
	content := `// subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason="Accepted staging risk"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	if err := auditor.ScanFile(tmpFile.Name()); err != nil {
		t.Fatalf("expected valid scan for // comment, got: %v", err)
	}

	ignored, entry := auditor.IsIgnored("SW-G-001", "staging.acme.com")
	if !ignored {
		t.Errorf("expected finding to be ignored with // comment")
	}
	if entry == nil || entry.Approver != "@sec-ops" {
		t.Errorf("expected approver @sec-ops, got %v", entry)
	}
}

func TestWildcardRuleRejected(t *testing.T) {
	content := `# subdomainwatch-ignore: * domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason="Blanket ignore"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	err = auditor.ScanFile(tmpFile.Name())
	if err == nil || !strings.Contains(err.Error(), "Wildcard '*' rule IDs are not permitted") {
		t.Errorf("expected error rejecting wildcard rule ID, got: %v", err)
	}
}

func TestExpirationExceeding90DaysFails(t *testing.T) {
	content := `# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2027-01-01 approver=@sec-ops reason="Too far out"
resource "aws_route53_record" "staging" {
  name = "staging.acme.com"
}
`
	tmpFile, err := os.CreateTemp("", "*.tf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(content)
	tmpFile.Close()

	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	err = auditor.ScanFile(tmpFile.Name())
	if err == nil || !strings.Contains(err.Error(), "90-day") {
		t.Errorf("expected error for expiry exceeding 90 days, got: %v", err)
	}
}
