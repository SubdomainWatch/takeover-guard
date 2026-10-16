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

type mockDetailedProber struct {
	responses map[string]struct {
		status   ProbeStatus
		sev      string
		rem      string
		errCause string
	}
}

func (m *mockDetailedProber) IsCloudProviderTarget(target string) bool {
	return true
}

func (m *mockDetailedProber) ProbeClaimability(fqdn, target string) (bool, string, string) {
	resp := m.responses[fqdn]
	return resp.status == ProbeStatusConfirmed, resp.sev, resp.rem
}

func (m *mockDetailedProber) ProbeClaimabilityDetailed(fqdn, target string) (ProbeStatus, string, string, string) {
	resp := m.responses[fqdn]
	return resp.status, resp.sev, resp.rem, resp.errCause
}

func TestAnalyzePlanIndeterminateAndClean(t *testing.T) {
	mockP := &mockDetailedProber{
		responses: map[string]struct {
			status   ProbeStatus
			sev      string
			rem      string
			errCause string
		}{
			"status.acme.com": {
				status:   ProbeStatusIndeterminate,
				errCause: "dial tcp: i/o timeout probing upstream",
			},
			"clean.acme.com": {
				status: ProbeStatusClean,
			},
			"vuln.acme.com": {
				status:   ProbeStatusConfirmed,
				sev:      SeverityCritical,
				rem:      "Reclaim S3 bucket",
				errCause: "",
			},
		},
	}

	plan := &PlanJSON{
		ResourceChanges: []ResourceChange{
			{
				Address: "cloudflare_record.status",
				Type:    "cloudflare_record",
				Change: ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name":    "status.acme.com",
						"type":    "CNAME",
						"content": "acme-status.herokuapp.com",
					},
				},
			},
			{
				Address: "cloudflare_record.clean",
				Type:    "cloudflare_record",
				Change: ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name":    "clean.acme.com",
						"type":    "CNAME",
						"content": "acme-clean.herokuapp.com",
					},
				},
			},
			{
				Address: "cloudflare_record.vuln",
				Type:    "cloudflare_record",
				Change: ChangeObj{
					Actions: []string{"create"},
					After: map[string]any{
						"name":    "vuln.acme.com",
						"type":    "CNAME",
						"content": "acme-vuln.s3.amazonaws.com",
					},
				},
			},
		},
	}

	evalRes, err := AnalyzePlan(plan, mockP)
	if err != nil {
		t.Fatalf("unexpected AnalyzePlan error: %v", err)
	}

	if evalRes.TotalModifiedRecords != 3 {
		t.Errorf("expected 3 modified records, got %d", evalRes.TotalModifiedRecords)
	}

	// 1 confirmed finding only
	if len(evalRes.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(evalRes.Findings))
	}
	if evalRes.Findings[0].FQDN != "vuln.acme.com" {
		t.Errorf("expected finding for vuln.acme.com, got %s", evalRes.Findings[0].FQDN)
	}

	// 1 indeterminate target
	if len(evalRes.IndeterminateTargets) != 1 {
		t.Fatalf("expected 1 indeterminate target, got %d", len(evalRes.IndeterminateTargets))
	}
	indet := evalRes.IndeterminateTargets[0]
	if indet.FQDN != "status.acme.com" {
		t.Errorf("expected indeterminate FQDN status.acme.com, got %s", indet.FQDN)
	}
	if indet.Target != "acme-status.herokuapp.com" {
		t.Errorf("expected indeterminate target acme-status.herokuapp.com, got %s", indet.Target)
	}
}

