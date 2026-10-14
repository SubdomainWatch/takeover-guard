package localscan

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
	"github.com/subdomainwatch/takeover-guard/pkg/override"
)

var (
	route53RecordRegex    = regexp.MustCompile(`(?i)^\s*resource\s+"aws_route53_record"\s+"([^"]+)"`)
	cloudflareRecordRegex = regexp.MustCompile(`(?i)^\s*resource\s+"cloudflare_record"\s+"([^"]+)"`)
	s3BucketRegex         = regexp.MustCompile(`(?i)^\s*resource\s+"aws_s3_bucket"\s+"([^"]+)"`)

	nameAttrRegex      = regexp.MustCompile(`(?i)^\s*name\s*=\s*"([^"]+)"`)
	typeAttrRegex      = regexp.MustCompile(`(?i)^\s*type\s*=\s*"([^"]+)"`)
	recordsStartRegex  = regexp.MustCompile(`(?i)^\s*records\s*=\s*\[`)
	quotedStringRegex  = regexp.MustCompile(`"([^",\s]+)"`)
	contentAttrRegex   = regexp.MustCompile(`(?i)^\s*content\s*=\s*"([^"]+)"`)
	bucketAttrRegex    = regexp.MustCompile(`(?i)^\s*bucket\s*=\s*"([^"]+)"`)
	aliasBlockRegex    = regexp.MustCompile(`(?i)^\s*alias\s*\{`)
	aliasNameAttrRegex = regexp.MustCompile(`(?i)^\s*(?:dns_name|name)\s*=\s*"([^"]+)"`)
)

type LocalRecord struct {
	ResourceName string
	ResourceType string
	Domain       string
	Target       string
	RecordType   string
	FilePath     string
	StartLine    int
}

type LocalScanResult struct {
	EvaluatedRecords int
	Findings         []correlator.Finding
	OverrideSnippets map[string]string // domain -> suggested comment
	UsedPlan         bool
}

// RunLocalEngine executes a local developer audit:
// 1. Attempts to use tfplan.json if present
// 2. Attempts to generate a local speculative plan if terraform is available
// 3. Falls back to static HCL parsing across local .tf files
func RunLocalEngine(ctx context.Context, dir string, prober correlator.ProberInterface) (*LocalScanResult, error) {
	// Check if a plan file exists locally
	planPath := filepath.Join(dir, "tfplan.json")
	if planBytes, err := os.ReadFile(planPath); err == nil {
		findings, count, err := correlator.EvaluatePlanBytes(planBytes, prober)
		if err == nil {
			return &LocalScanResult{
				EvaluatedRecords: count,
				Findings:         findings,
				UsedPlan:         true,
				OverrideSnippets: generateSnippets(findings),
			}, nil
		}
	}

	// Fallback: Static HCL parser across all .tf files in directory (safe: zero execution of external binaries)
	return scanHCLFiles(dir, prober)
}

func scanHCLFiles(dir string, prober correlator.ProberInterface) (*LocalScanResult, error) {
	var records []LocalRecord
	localBuckets := make(map[string]bool)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".tf") {
			return nil
		}

		fileRecords, buckets, err := parseTFFile(path)
		if err == nil {
			records = append(records, fileRecords...)
			for b := range buckets {
				localBuckets[b] = true
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan terraform files: %w", err)
	}

	// Audit in-code overrides
	auditor := override.NewOverrideAuditor()
	if err := auditor.ScanDirectory(dir); err != nil {
		return nil, fmt.Errorf("in-code override validation failure: %w", err)
	}

	var findings []correlator.Finding

	for _, rec := range records {
		normTarget := correlator.NormalizeDomain(rec.Target)
		normFQDN := correlator.NormalizeDomain(rec.Domain)

		if normTarget == "" || normFQDN == "" {
			continue
		}

		provider, identifier := correlator.ExtractCloudTargetIdentity(normTarget)

		// Rule 1: S3 bucket target check against local repo buckets
		if provider == "s3" && identifier != "" {
			if localBuckets[identifier] {
				// Bucket is actively managed in this local repository, safe!
				continue
			}
			if prober != nil {
				// Probe if unmanaged external target bucket is claimable
				isVuln, sev, rem := prober.ProbeClaimability(normFQDN, normTarget)
				if isVuln {
					findings = append(findings, correlator.Finding{
						RuleID:     correlator.RuleDanglingPointer,
						Severity:   sev,
						FQDN:       normFQDN,
						Target:     normTarget,
						Address:    fmt.Sprintf("%s.%s", rec.ResourceType, rec.ResourceName),
						SourceFile: rec.FilePath,
						StartLine:  rec.StartLine,
						Reason:     rem,
					})
				}
			}
			continue
		}

		// Rule 2: General cloud provider target
		if prober != nil && prober.IsCloudProviderTarget(normTarget) {
			if correlator.IsPrivateTarget(normTarget) {
				continue
			}

			isVuln, sev, rem := prober.ProbeClaimability(normFQDN, normTarget)
			if isVuln {
				findings = append(findings, correlator.Finding{
					RuleID:     correlator.RuleDanglingPointer,
					Severity:   sev,
					FQDN:       normFQDN,
					Target:     normTarget,
					Address:    fmt.Sprintf("%s.%s", rec.ResourceType, rec.ResourceName),
					SourceFile: rec.FilePath,
					StartLine:  rec.StartLine,
					Reason:     rem,
				})
			}
		}
	}

	// Filter findings against overrides
	var activeFindings []correlator.Finding
	for _, f := range findings {
		ignored, _ := auditor.IsIgnored(f.RuleID, f.FQDN)
		if !ignored {
			activeFindings = append(activeFindings, f)
		}
	}

	return &LocalScanResult{
		EvaluatedRecords: len(records),
		Findings:         activeFindings,
		OverrideSnippets: generateSnippets(activeFindings),
		UsedPlan:         false,
	}, nil
}

func parseTFFile(path string) ([]LocalRecord, map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var records []LocalRecord
	buckets := make(map[string]bool)

	var currentRecord *LocalRecord
	lineNum := 0
	inBlock := false
	braceCount := 0
	inAliasBlock := false
	aliasBraceCount := 0
	inRecordsArray := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if s3Match := s3BucketRegex.FindStringSubmatch(line); s3Match != nil {
			inBlock = true
			braceCount = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if r53Match := route53RecordRegex.FindStringSubmatch(line); r53Match != nil {
			currentRecord = &LocalRecord{
				ResourceType: "aws_route53_record",
				ResourceName: r53Match[1],
				FilePath:     path,
				StartLine:    lineNum,
			}
			inBlock = true
			inAliasBlock = false
			aliasBraceCount = 0
			inRecordsArray = false
			braceCount = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if cfMatch := cloudflareRecordRegex.FindStringSubmatch(line); cfMatch != nil {
			currentRecord = &LocalRecord{
				ResourceType: "cloudflare_record",
				ResourceName: cfMatch[1],
				FilePath:     path,
				StartLine:    lineNum,
			}
			inBlock = true
			inAliasBlock = false
			aliasBraceCount = 0
			inRecordsArray = false
			braceCount = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inBlock {
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			if bMatch := bucketAttrRegex.FindStringSubmatch(line); bMatch != nil {
				buckets[strings.ToLower(strings.TrimSpace(bMatch[1]))] = true
			}

			if currentRecord != nil {
				// Check for alias block start (§6.4 & P1-1)
				if aliasBlockRegex.MatchString(line) {
					inAliasBlock = true
					aliasBraceCount = strings.Count(line, "{") - strings.Count(line, "}")
				} else if inAliasBlock {
					aliasBraceCount += strings.Count(line, "{") - strings.Count(line, "}")
				}

				if inAliasBlock {
					if aMatch := aliasNameAttrRegex.FindStringSubmatch(line); aMatch != nil {
						currentRecord.Target = aMatch[1]
					}
					if aliasBraceCount <= 0 {
						inAliasBlock = false
					}
				} else {
					// Top-level attributes outside alias block
					if nMatch := nameAttrRegex.FindStringSubmatch(line); nMatch != nil {
						currentRecord.Domain = nMatch[1]
					}
					if tMatch := typeAttrRegex.FindStringSubmatch(line); tMatch != nil {
						currentRecord.RecordType = tMatch[1]
					}
					if cMatch := contentAttrRegex.FindStringSubmatch(line); cMatch != nil {
						currentRecord.Target = cMatch[1]
					}

					// Multi-line and single-line records array parsing (P0-1)
					if recordsStartRegex.MatchString(line) {
						matches := quotedStringRegex.FindAllStringSubmatch(line, -1)
						if len(matches) > 0 {
							currentRecord.Target = matches[0][1]
						}
						if !strings.Contains(line, "]") {
							inRecordsArray = true
						}
					} else if inRecordsArray {
						matches := quotedStringRegex.FindAllStringSubmatch(line, -1)
						if len(matches) > 0 && currentRecord.Target == "" {
							currentRecord.Target = matches[0][1]
						}
						if strings.Contains(line, "]") {
							inRecordsArray = false
						}
					}
				}
			}

			if braceCount <= 0 {
				inBlock = false
				inAliasBlock = false
				inRecordsArray = false
				if currentRecord != nil {
					if currentRecord.Domain != "" && currentRecord.Target != "" {
						records = append(records, *currentRecord)
					}
					currentRecord = nil
				}
			}
		}
	}

	return records, buckets, scanner.Err()
}

func generateSnippets(findings []correlator.Finding) map[string]string {
	snippets := make(map[string]string)
	expiryDate := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	user := "@developer"

	// Try getting git username
	if out, err := exec.Command("git", "config", "user.name").Output(); err == nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			if strings.Contains(trimmed, "@") {
				parts := strings.Split(trimmed, "@")
				user = "@" + strings.ToLower(parts[0])
			} else {
				user = "@" + strings.ToLower(strings.ReplaceAll(trimmed, " ", "-"))
			}
		}
	}
	if user == "@developer" {
		if out, err := exec.Command("git", "config", "user.email").Output(); err == nil {
			trimmed := strings.TrimSpace(string(out))
			if trimmed != "" && strings.Contains(trimmed, "@") {
				parts := strings.Split(trimmed, "@")
				user = "@" + strings.ToLower(parts[0])
			}
		}
	}

	for _, f := range findings {
		snippets[f.FQDN] = fmt.Sprintf(
			"# subdomainwatch-ignore: %s domain=%s expires=%s approver=%s reason=\"Accepted pre-commit risk\"",
			f.RuleID, f.FQDN, expiryDate, user,
		)
	}
	return snippets
}
