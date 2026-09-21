package correlator

import (
	"testing"
)

type mockProber struct {
	isCloudTarget bool
	isVuln        bool
	severity      string
	remediation   string
}

func (m *mockProber) IsCloudProviderTarget(target string) bool {
	return m.isCloudTarget
}

func (m *mockProber) ProbeClaimability(fqdn, target string) (bool, string, string) {
	return m.isVuln, m.severity, m.remediation
}

func TestUncoordinatedS3Deletion(t *testing.T) {
	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_s3_bucket.staging_assets",
				Type:    "aws_s3_bucket",
				Change: ChangeObj{
					Actions: []string{"delete"},
					Before: map[string]any{
						"bucket": "acme-staging-bucket",
					},
				},
			},
			{
				Address: "aws_route53_record.staging",
				Type:    "aws_route53_record",
				Change: ChangeObj{
					Actions: []string{"no-op"},
					After: map[string]any{
						"name": "staging.acme.com",
						"type": "CNAME",
						"records": []any{
							"acme-staging-bucket.s3.amazonaws.com",
						},
					},
				},
			},
		},
	}

	findings, modifiedCount, err := EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if modifiedCount != 1 {
		t.Errorf("expected 1 modified record, got %d", modifiedCount)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != RuleUncoordinatedOrphan {
		t.Errorf("expected rule %s, got %s", RuleUncoordinatedOrphan, f.RuleID)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected severity %s, got %s", SeverityCritical, f.Severity)
	}
	if f.FQDN != "staging.acme.com" {
		t.Errorf("expected FQDN staging.acme.com, got %s", f.FQDN)
	}
}

func TestCoordinatedDeletion(t *testing.T) {
	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_s3_bucket.staging_assets",
				Type:    "aws_s3_bucket",
				Change: ChangeObj{
					Actions: []string{"delete"},
					Before: map[string]any{
						"bucket": "acme-staging-bucket",
					},
				},
			},
			{
				Address: "aws_route53_record.staging",
				Type:    "aws_route53_record",
				Change: ChangeObj{
					Actions: []string{"delete"},
					Before: map[string]any{
						"name": "staging.acme.com",
						"type": "CNAME",
						"records": []any{
							"acme-staging-bucket.s3.amazonaws.com",
						},
					},
				},
			},
		},
	}

	findings, _, err := EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for coordinated deletion, got %d", len(findings))
	}
}

func TestRoute53AliasResolution(t *testing.T) {
	// Test CloudFront alias (dns_name) and S3 Website alias (name)
	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: `aws_s3_bucket.website["prod"]`,
				Type:    "aws_s3_bucket",
				Change: ChangeObj{
					Actions: []string{"delete"},
					Before: map[string]any{
						"bucket": "acme-prod-site",
					},
				},
			},
			{
				Address: "aws_route53_record.website_alias",
				Type:    "aws_route53_record",
				Change: ChangeObj{
					Actions: []string{"update"},
					After: map[string]any{
						"name": "site.acme.com",
						"type": "A",
						"alias": map[string]any{
							"name":    "acme-prod-site.s3-website-us-east-1.amazonaws.com",
							"zone_id": "Z3AQBSTGFYJSTF",
						},
					},
				},
			},
		},
	}

	findings, _, err := EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for alias target matching deleted bucket, got %d", len(findings))
	}
	if findings[0].RuleID != RuleUncoordinatedOrphan {
		t.Errorf("expected rule %s, got %s", RuleUncoordinatedOrphan, findings[0].RuleID)
	}
}

func TestAfterUnknownDynamicRecord(t *testing.T) {
	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_route53_record.dynamic",
				Type:    "aws_route53_record",
				Change: ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name": "dynamic.acme.com",
					},
					AfterUnknown: map[string]any{
						"records": true,
					},
				},
			},
		},
	}

	findings, _, err := EvaluatePlan(plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for computed target, got %d", len(findings))
	}
	if findings[0].RuleID != RuleComputedTarget {
		t.Errorf("expected rule %s, got %s", RuleComputedTarget, findings[0].RuleID)
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected severity %s, got %s", SeverityWarning, findings[0].Severity)
	}
}

func TestCloudflareRecordExtraction(t *testing.T) {
	mockP := &mockProber{
		isCloudTarget: true,
		isVuln:        true,
		severity:      SeverityCritical,
		remediation:   "Reclaim Heroku app",
	}

	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: "cloudflare_record.api",
				Type:    "cloudflare_record",
				Change: ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name":    "api.acme.com",
						"type":    "CNAME",
						"content": "acme-api.herokudns.com",
					},
				},
			},
		},
	}

	findings, _, err := EvaluatePlan(plan, mockP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for vulnerable cloudflare record, got %d", len(findings))
	}
	if findings[0].RuleID != RuleDanglingPointer {
		t.Errorf("expected rule %s, got %s", RuleDanglingPointer, findings[0].RuleID)
	}
	if findings[0].Target != "acme-api.herokudns.com" {
		t.Errorf("expected target acme-api.herokudns.com, got %s", findings[0].Target)
	}
}
