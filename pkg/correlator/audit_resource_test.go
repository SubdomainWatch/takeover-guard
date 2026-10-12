package correlator

import "testing"

type auditMockProber struct{ target, fqdn string }

func (m *auditMockProber) IsCloudProviderTarget(target string) bool { return target == m.target }
func (m *auditMockProber) ProbeClaimability(fqdn, target string) (bool, string, string) {
	m.fqdn = fqdn
	return true, SeverityCritical, "confirmed test fingerprint"
}

func TestExtractAzureDNSCNAME(t *testing.T) {
	const fqdn, target = "www.example.com", "orphan.azurewebsites.net"
	p := &auditMockProber{target: target}
	plan := &PlanJSON{ResourceChanges: []ResourceChange{{
		Address: "azurerm_dns_cname_record.web",
		Type:    "azurerm_dns_cname_record",
		Change: ChangeObj{Actions: []string{"create"}, After: map[string]any{
			"name": "www", "zone_name": "example.com", "record": target,
		}},
	}}}

	findings, count, err := EvaluatePlan(plan, p)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(findings) != 1 {
		t.Fatalf("expected one extracted/probed record, got count=%d findings=%d", count, len(findings))
	}
	if p.fqdn != fqdn || findings[0].Target != target {
		t.Fatalf("wrong correlation: fqdn=%q target=%q", p.fqdn, findings[0].Target)
	}
}

func TestExtractGoogleCloudDNSCNAME(t *testing.T) {
	const fqdn, target = "www.example.com", "orphan.azurewebsites.net"
	p := &auditMockProber{target: target}
	plan := &PlanJSON{ResourceChanges: []ResourceChange{{
		Address: "google_dns_record_set.web",
		Type:    "google_dns_record_set",
		Change: ChangeObj{Actions: []string{"create"}, After: map[string]any{
			"name": fqdn + ".", "type": "CNAME", "rrdatas": []any{target + "."},
		}},
	}}}

	findings, count, err := EvaluatePlan(plan, p)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(findings) != 1 {
		t.Fatalf("expected one extracted/probed record, got count=%d findings=%d", count, len(findings))
	}
	if p.fqdn != fqdn || findings[0].Target != target {
		t.Fatalf("wrong correlation: fqdn=%q target=%q", p.fqdn, findings[0].Target)
	}
}
