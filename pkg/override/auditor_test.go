package override

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scanTFContent(t *testing.T, content string) (*OverrideAuditor, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	auditor := NewOverrideAuditor()
	auditor.SetNow(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))
	return auditor, auditor.ScanFile(path)
}

func TestOverrideAuditorScenarios(t *testing.T) {
	const resBlock = "resource \"aws_route53_record\" \"staging\" {\n  name = \"staging.acme.com\"\n}\n"

	cases := []struct {
		name        string
		content     string
		wantErrSub  string
		wantIgnored bool
		wantApprove string
	}{
		{
			name:        "valid line N-1 hash comment",
			content:     "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Accepted staging risk\"\n" + resBlock,
			wantIgnored: true,
			wantApprove: "@sec-ops",
		},
		{
			name:        "valid one blank line between comment and resource",
			content:     "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Accepted staging risk\"\n\n" + resBlock,
			wantIgnored: true,
			wantApprove: "@sec-ops",
		},
		{
			name:        "valid double-slash comment",
			content:     "// subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Accepted staging risk\"\n" + resBlock,
			wantIgnored: true,
			wantApprove: "@sec-ops",
		},
		{
			name:        "expired override logs warning without failing build or suppressing finding",
			content:     "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-09-01 approver=@sec-ops reason=\"Past expiry\"\n" + resBlock,
			wantIgnored: false,
		},
		{
			name:       "detached comment (>1 blank line) fails",
			content:    "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Accepted\"\n\n\n" + resBlock,
			wantErrSub: "Detached",
		},
		{
			name:       "detached comment at EOF without resource fails",
			content:    "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"EOF orphan\"\n",
			wantErrSub: "end of file",
		},
		{
			name:       "wildcard rule ID rejected",
			content:    "# subdomainwatch-ignore: * domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Blanket ignore\"\n" + resBlock,
			wantErrSub: "Wildcard '*' rule IDs are not permitted",
		},
		{
			name:       "invalid date format rejected",
			content:    "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=15-10-2026 approver=@sec-ops reason=\"Bad date\"\n" + resBlock,
			wantErrSub: "invalid expires date format",
		},
		{
			name:       "expiration exceeding 90 days fails",
			content:    "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2027-01-01 approver=@sec-ops reason=\"Too far out\"\n" + resBlock,
			wantErrSub: "90-day",
		},
		{
			name:       "malformed directive fails closed",
			content:    "# subdomainwatch-ignore: SW-G-001 expires=2026-10-15 domain=staging.acme.com approver=@sec-ops\n" + resBlock,
			wantErrSub: "Malformed subdomainwatch-ignore directive",
		},
		{
			name: "stacked overrides above single resource both register",
			content: "# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Rule 1\"\n" +
				"# subdomainwatch-ignore: SW-G-002 domain=staging.acme.com expires=2026-10-15 approver=@sec-ops reason=\"Rule 2\"\n" + resBlock,
			wantIgnored: true,
			wantApprove: "@sec-ops",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditor, err := scanTFContent(t, tc.content)
			if tc.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErrSub, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected scan error: %v", err)
			}
			ignored, entry := auditor.IsIgnored("SW-G-001", "staging.acme.com.")
			if ignored != tc.wantIgnored {
				t.Fatalf("IsIgnored = %v, want %v", ignored, tc.wantIgnored)
			}
			if tc.wantApprove != "" && (entry == nil || entry.Approver != tc.wantApprove) {
				t.Errorf("expected approver %q, got %+v", tc.wantApprove, entry)
			}
		})
	}
}
