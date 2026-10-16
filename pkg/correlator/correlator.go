package correlator

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	s3Pattern        = regexp.MustCompile(`^([a-z0-9.-]+)\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com$`)
	herokuPattern    = regexp.MustCompile(`^([a-z0-9-]+)\.(?:herokudns|herokuapp)\.com$`)
	githubPattern    = regexp.MustCompile(`^([a-z0-9-]+)\.github\.io$`)
	azurePattern     = regexp.MustCompile(`^([a-z0-9-]+)\.(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azurefd\.net)$`)
	netlifyPattern   = regexp.MustCompile(`^([a-z0-9-]+)\.netlify\.(?:app|com)$`)
	readmePattern    = regexp.MustCompile(`^([a-z0-9-]+)\.readme\.io$`)
	surgePattern     = regexp.MustCompile(`^([a-z0-9-]+)\.surge\.sh$`)
	shopifyPattern   = regexp.MustCompile(`^([a-z0-9-]+)\.myshopify\.com$`)
	fastlyPattern    = regexp.MustCompile(`^([a-z0-9-]+)\.fastly\.net$`)
	bitbucketPattern = regexp.MustCompile(`^([a-z0-9-]+)\.bitbucket\.io$`)
	ghostPattern     = regexp.MustCompile(`^([a-z0-9-]+)\.ghost\.io$`)
	flyPattern       = regexp.MustCompile(`^([a-z0-9-]+)\.(?:edgeapp\.net|fly\.dev)$`)
)

type DnsRecordEntry struct {
	FQDN       string
	Target     string
	Address    string
	RecordType string
}

// NormalizeDomain normalizes domain to lowercase, trimmed, without trailing dot.
func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}
	d := strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimSuffix(d, ".")
}

// ExtractCloudTargetIdentity extracts provider and resource name from canonical CNAME/Alias destination.
func ExtractCloudTargetIdentity(target string) (provider, identifier string) {
	norm := NormalizeDomain(target)
	if norm == "" {
		return "", ""
	}

	if match := s3Pattern.FindStringSubmatch(norm); match != nil {
		return "s3", match[1]
	}
	if match := herokuPattern.FindStringSubmatch(norm); match != nil {
		return "heroku", match[1]
	}
	if match := githubPattern.FindStringSubmatch(norm); match != nil {
		return "github_pages", match[1]
	}
	if match := azurePattern.FindStringSubmatch(norm); match != nil {
		return "azure", match[1]
	}
	if match := netlifyPattern.FindStringSubmatch(norm); match != nil {
		return "netlify", match[1]
	}
	if match := readmePattern.FindStringSubmatch(norm); match != nil {
		return "readme", match[1]
	}
	if match := surgePattern.FindStringSubmatch(norm); match != nil {
		return "surge", match[1]
	}
	if match := shopifyPattern.FindStringSubmatch(norm); match != nil {
		return "shopify", match[1]
	}
	if match := fastlyPattern.FindStringSubmatch(norm); match != nil {
		return "fastly", match[1]
	}
	if match := bitbucketPattern.FindStringSubmatch(norm); match != nil {
		return "bitbucket", match[1]
	}
	if match := ghostPattern.FindStringSubmatch(norm); match != nil {
		return "ghost", match[1]
	}
	if match := flyPattern.FindStringSubmatch(norm); match != nil {
		return "fly", match[1]
	}

	return "", ""
}

// IsPrivateTarget checks if target is RFC 1918 or internal VPC endpoint (§6.1)
func IsPrivateTarget(target string) bool {
	norm := NormalizeDomain(target)
	if strings.Contains(norm, ".vpc-endpoints.") ||
		strings.HasSuffix(norm, ".internal") ||
		strings.HasSuffix(norm, ".local") {
		return true
	}

	ip := net.ParseIP(norm)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// EvaluatePlanBytes parses raw Terraform plan JSON and runs the correlation evaluation
func EvaluatePlanBytes(planBytes []byte, prober ProberInterface) ([]Finding, int, error) {
	res, err := AnalyzePlanBytes(planBytes, prober)
	if err != nil {
		return nil, 0, err
	}
	return res.Findings, res.TotalModifiedRecords, nil
}

// AnalyzePlanBytes parses raw Terraform plan JSON and returns detailed evaluation results
func AnalyzePlanBytes(planBytes []byte, prober ProberInterface) (*EvaluationResult, error) {
	var plan PlanJSON
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse terraform plan JSON: %w", err)
	}

	return AnalyzePlan(&plan, prober)
}

// EvaluatePlan evaluates parsed Terraform plan against takeover rules
func EvaluatePlan(plan *PlanJSON, prober ProberInterface) ([]Finding, int, error) {
	res, err := AnalyzePlan(plan, prober)
	if err != nil {
		return nil, 0, err
	}
	return res.Findings, res.TotalModifiedRecords, nil
}

// AnalyzePlan evaluates parsed Terraform plan against takeover rules and collects indeterminate probe targets
func AnalyzePlan(plan *PlanJSON, prober ProberInterface) (*EvaluationResult, error) {
	deletedCloudResources := make(map[string]map[string]struct{})
	activeCloudResources := make(map[string]map[string]struct{})
	deletedDnsRecords := make(map[string]string)
	activeDnsRecords := make(map[string]DnsRecordEntry)
	var findings []Finding
	var indeterminateTargets []IndeterminateTarget

	totalModifiedDnsRecords := 0

	for _, change := range plan.ResourceChanges {
		rtype := change.Type
		actions := change.Change.Actions
		before := change.Change.Before
		after := change.Change.After
		afterUnknown := change.Change.AfterUnknown
		address := change.Address

		isDelete := containsAction(actions, "delete")
		isCreate := containsAction(actions, "create")
		isUpdate := containsAction(actions, "update")
		isNoOp := containsAction(actions, "no-op") || len(actions) == 0

		// -------------------------------------------------------------
		// 1. AWS S3 BUCKET LIFECYCLE (Supports for_each and modules)
		// -------------------------------------------------------------
		if rtype == "aws_s3_bucket" {
			bucketName := getString(before, "bucket")
			if bucketName == "" {
				bucketName = getString(before, "id")
			}
			if bucketName == "" {
				bucketName = getString(after, "bucket")
			}
			if bucketName != "" {
				bucketName = strings.ToLower(strings.TrimSpace(bucketName))
				if isDelete {
					addResource(deletedCloudResources, "s3", bucketName)
				} else if isCreate || isNoOp || isUpdate {
					addResource(activeCloudResources, "s3", bucketName)
				}
			}
		}

		// -------------------------------------------------------------
		// 2. HEROKU APP LIFECYCLE
		// -------------------------------------------------------------
		if rtype == "heroku_app" {
			appName := getString(before, "name")
			if appName == "" {
				appName = getString(after, "name")
			}
			if appName != "" {
				appName = strings.ToLower(strings.TrimSpace(appName))
				if isDelete {
					addResource(deletedCloudResources, "heroku", appName)
				} else {
					addResource(activeCloudResources, "heroku", appName)
				}
			}
		}

		// -------------------------------------------------------------
		// 3. ROUTE 53 DNS RECORD LIFECYCLE (Standard CNAME & ALIAS)
		// -------------------------------------------------------------
		if rtype == "aws_route53_record" {
			totalModifiedDnsRecords++

			recordName := getString(before, "name")
			if recordName == "" {
				recordName = getString(after, "name")
			}
			fqdn := NormalizeDomain(recordName)

			// Check if target values are unknown (computed after apply)
			if isBoolTrue(afterUnknown, "records") || isBoolTrue(afterUnknown, "alias") {
				findings = append(findings, Finding{
					RuleID:   RuleComputedTarget,
					Severity: SeverityWarning,
					FQDN:     fqdn,
					Target:   "COMPUTED_AT_APPLY",
					Address:  address,
					Reason:   fmt.Sprintf("DNS record '%s' (%s) has dynamic computed targets unresolvable at plan time. Flagged for mandatory Post-Apply Sentinel verification.", fqdn, address),
				})
				continue
			}

			var target string

			// Case A: Standard CNAME
			recType := getString(before, "type")
			if recType == "" {
				recType = getString(after, "type")
			}

			if strings.EqualFold(recType, "CNAME") {
				rawRecords := getSlice(before, "records")
				if !isDelete {
					rawRecords = getSlice(after, "records")
				}
				if len(rawRecords) > 0 {
					target = NormalizeDomain(fmt.Sprint(rawRecords[0]))
				}
			}

			// Case B: Route53 ALIAS (CloudFront or S3 Website)
			// S3 Website uses 'name', CloudFront uses 'dns_name'
			aliasData := getMapOrSliceMap(before, "alias")
			if !isDelete {
				aliasData = getMapOrSliceMap(after, "alias")
			}
			if aliasData != nil {
				rawAliasTarget := getString(aliasData, "dns_name")
				if rawAliasTarget == "" {
					rawAliasTarget = getString(aliasData, "name")
				}
				if rawAliasTarget != "" {
					target = NormalizeDomain(rawAliasTarget)
				}
			}

			if fqdn != "" && target != "" {
				if isDelete {
					deletedDnsRecords[fqdn] = target
				} else {
					activeDnsRecords[fqdn] = DnsRecordEntry{
						FQDN:       fqdn,
						Target:     target,
						Address:    address,
						RecordType: recType,
					}
				}
			}
		}

		// -------------------------------------------------------------
		// 4. CLOUDFLARE RECORD LIFECYCLE (§6.2 & Round 3 Refinement #3)
		// -------------------------------------------------------------
		if rtype == "cloudflare_record" {
			totalModifiedDnsRecords++

			recordName := getString(before, "name")
			if recordName == "" {
				recordName = getString(after, "name")
			}
			fqdn := NormalizeDomain(recordName)

			if isBoolTrue(afterUnknown, "content") {
				findings = append(findings, Finding{
					RuleID:   RuleComputedTarget,
					Severity: SeverityWarning,
					FQDN:     fqdn,
					Target:   "COMPUTED_AT_APPLY",
					Address:  address,
					Reason:   fmt.Sprintf("Cloudflare record '%s' (%s) has dynamic content unresolvable at plan time. Flagged for mandatory Post-Apply Sentinel verification.", fqdn, address),
				})
				continue
			}

			content := getString(before, "content")
			if !isDelete {
				content = getString(after, "content")
			}

			recType := getString(before, "type")
			if recType == "" {
				recType = getString(after, "type")
			}

			if fqdn != "" && content != "" {
				target := NormalizeDomain(content)
				if isDelete {
					deletedDnsRecords[fqdn] = target
				} else {
					activeDnsRecords[fqdn] = DnsRecordEntry{
						FQDN:       fqdn,
						Target:     target,
						Address:    address,
						RecordType: recType,
					}
				}
			}
		}

		// -------------------------------------------------------------
		// 5. AZURE DNS CNAME RECORD LIFECYCLE
		// -------------------------------------------------------------
		if rtype == "azurerm_dns_cname_record" {
			totalModifiedDnsRecords++
			fqdn := azureRecordFQDN(before)
			if fqdn == "" {
				fqdn = azureRecordFQDN(after)
			}
			target := getString(before, "record")
			if !isDelete {
				target = getString(after, "record")
			}
			target = NormalizeDomain(target)
			if fqdn != "" && target != "" {
				if isDelete {
					deletedDnsRecords[fqdn] = target
				} else {
					activeDnsRecords[fqdn] = DnsRecordEntry{FQDN: fqdn, Target: target, Address: address, RecordType: "CNAME"}
				}
			}
		}

		// -------------------------------------------------------------
		// 6. GOOGLE CLOUD DNS CNAME RECORD LIFECYCLE
		// -------------------------------------------------------------
		if rtype == "google_dns_record_set" {
			recType := getString(before, "type")
			if recType == "" {
				recType = getString(after, "type")
			}
			if strings.EqualFold(recType, "CNAME") {
				totalModifiedDnsRecords++
				name := getString(before, "name")
				if name == "" {
					name = getString(after, "name")
				}
				fqdn := NormalizeDomain(name)
				values := getSlice(after, "rrdatas")
				if isDelete {
					values = getSlice(before, "rrdatas")
				}
				if fqdn != "" && len(values) > 0 {
					target := NormalizeDomain(fmt.Sprint(values[0]))
					if isDelete {
						deletedDnsRecords[fqdn] = target
					} else {
						activeDnsRecords[fqdn] = DnsRecordEntry{FQDN: fqdn, Target: target, Address: address, RecordType: recType}
					}
				}
			}
		}
	}

	// -----------------------------------------------------------------
	// 5. CORRELATION EVALUATION
	// -----------------------------------------------------------------
	for fqdn, entry := range activeDnsRecords {
		target := entry.Target
		provider, identifier := ExtractCloudTargetIdentity(target)

		// Rule 1: Coordinated Deletion Check
		// If DNS record is also deleted with the same target, safe
		if delTarget, exists := deletedDnsRecords[fqdn]; exists && delTarget == target {
			continue
		}

		// Rule 2: Uncoordinated Resource Orphan (Same-PR Bug)
		if provider != "" {
			if deletedSet, exists := deletedCloudResources[provider]; exists {
				if _, isDeleted := deletedSet[identifier]; isDeleted {
					findings = append(findings, Finding{
						RuleID:   RuleUncoordinatedOrphan,
						Severity: SeverityCritical,
						FQDN:     fqdn,
						Target:   target,
						Address:  entry.Address,
						Reason:   fmt.Sprintf("Underlying %s resource '%s' is deleted in this plan, but DNS record '%s' remains active. Immediate takeover vulnerability.", provider, identifier, fqdn),
					})
					continue
				}
			}
		}

		// Rule 3: Live Authority Probing for External/Unmanaged Targets
		if prober != nil && prober.IsCloudProviderTarget(target) {
			// If cloud resource is being actively created/active in this plan, skip claim check
			if provider != "" {
				if activeSet, exists := activeCloudResources[provider]; exists {
					if _, isActive := activeSet[identifier]; isActive {
						continue // Safe provisioning
					}
				}
			}

			// Private hosted zone / RFC 1918 guard (§6.1)
			if IsPrivateTarget(target) {
				continue
			}

			var status ProbeStatus
			var sev, rem, errReason string

			if dp, ok := prober.(DetailedProber); ok {
				status, sev, rem, errReason = dp.ProbeClaimabilityDetailed(fqdn, target)
			} else {
				isVuln, s, r := prober.ProbeClaimability(fqdn, target)
				if isVuln {
					status = ProbeStatusConfirmed
					sev, rem = s, r
				} else {
					status = ProbeStatusClean
				}
			}

			switch status {
			case ProbeStatusConfirmed:
				findings = append(findings, Finding{
					RuleID:   RuleDanglingPointer,
					Severity: sev,
					FQDN:     fqdn,
					Target:   target,
					Address:  entry.Address,
					Reason:   rem,
				})
			case ProbeStatusIndeterminate:
				reason := fmt.Sprintf("External probe indeterminate for %s -> %s", fqdn, target)
				if errReason != "" {
					reason = fmt.Sprintf("External probe indeterminate for %s -> %s: %s", fqdn, target, errReason)
				}
				indeterminateTargets = append(indeterminateTargets, IndeterminateTarget{
					FQDN:    fqdn,
					Target:  target,
					Address: entry.Address,
					Reason:  reason,
				})
			case ProbeStatusClean:
				// Target verified clean
			}
		}
	}

	return &EvaluationResult{
		Findings:             findings,
		IndeterminateTargets: indeterminateTargets,
		TotalModifiedRecords: totalModifiedDnsRecords,
	}, nil
}

// Helpers

func containsAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

func addResource(m map[string]map[string]struct{}, provider, id string) {
	if m[provider] == nil {
		m[provider] = make(map[string]struct{})
	}
	m[provider][id] = struct{}{}
}

func azureRecordFQDN(attrs map[string]any) string {
	name := NormalizeDomain(getString(attrs, "name"))
	zone := NormalizeDomain(getString(attrs, "zone_name"))
	if name == "" || zone == "" {
		return ""
	}
	return name + "." + zone
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if val, ok := m[key]; ok && val != nil {
		return strings.TrimSpace(fmt.Sprint(val))
	}
	return ""
}

func isBoolTrue(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	if val, ok := m[key]; ok && val != nil {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getSlice(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	if val, ok := m[key]; ok && val != nil {
		if s, ok := val.([]any); ok {
			return s
		}
	}
	return nil
}

func getMapOrSliceMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	val, ok := m[key]
	if !ok || val == nil {
		return nil
	}
	if resMap, ok := val.(map[string]any); ok {
		return resMap
	}
	if slice, ok := val.([]any); ok && len(slice) > 0 {
		if resMap, ok := slice[0].(map[string]any); ok {
			return resMap
		}
	}
	return nil
}
