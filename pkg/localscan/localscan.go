package localscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
	"github.com/subdomainwatch/takeover-guard/pkg/override"
)

var (
	route53RecordRegex    = regexp.MustCompile(`(?i)^\s*resource\s+"aws_route53_record"\s+"([^"]+)"`)
	cloudflareRecordRegex = regexp.MustCompile(`(?i)^\s*resource\s+"cloudflare_record"\s+"([^"]+)"`)
	azureRecordRegex      = regexp.MustCompile(`(?i)^\s*resource\s+"azurerm_dns_(?:cname|a|txt)_record"\s+"([^"]+)"`)
	gcpRecordRegex        = regexp.MustCompile(`(?i)^\s*resource\s+"google_dns_record_set"\s+"([^"]+)"`)
	s3BucketRegex         = regexp.MustCompile(`(?i)^\s*resource\s+"aws_s3_bucket"\s+"([^"]+)"`)

	aliasBlockRegex  = regexp.MustCompile(`(?i)^\s*alias\s*\{`)
	aliasTargetRegex = regexp.MustCompile(`(?i)^\s*(?:dns_name|name)\s*=\s*"([^"]+)"`)

	nameAttrRegex     = regexp.MustCompile(`(?i)^\s*name\s*=\s*"([^"]+)"`)
	zoneNameAttrRegex = regexp.MustCompile(`(?i)^\s*zone_name\s*=\s*"([^"]+)"`)
	recordAttrRegex   = regexp.MustCompile(`(?i)^\s*(?:record|value|cname|content)\s*=\s*"([^"]+)"`)
	typeAttrRegex     = regexp.MustCompile(`(?i)^\s*type\s*=\s*"([^"]+)"`)
	bucketAttrRegex   = regexp.MustCompile(`(?i)^\s*bucket\s*=\s*"([^"]+)"`)
	listItemRegex     = regexp.MustCompile(`"([^"]+)"`)
)

// CandidateRecord represents a statically parsed DNS or storage resource from HCL.
type CandidateRecord struct {
	Provider     string
	ResourceName string
	Name         string
	ZoneName     string
	RecordType   string
	Targets      []string
	FilePath     string
	LineNumber   int
}

// LocalScanOptions configures the static workspace scan.
type LocalScanOptions struct {
	WorkspaceDir string
	PlanJSONPath string
	OverridePath string
	Concurrency  int
	Timeout      time.Duration
	Prober       correlator.ProberInterface
}

// LocalScanResult holds the output of the local scanning engine.
type LocalScanResult struct {
	EvaluatedRecords     int
	Findings             []correlator.Finding
	IndeterminateTargets []correlator.IndeterminateTarget
	OverrideSnippets     map[string]string // domain -> suggested comment
	UsedPlan             bool
}

// RunLocalEngine performs a side-effect-free static audit of local HCL files
// and optional pre-generated plan data, correlating results against active overrides.
func RunLocalEngine(ctx context.Context, opts LocalScanOptions) (*LocalScanResult, error) {
	if opts.WorkspaceDir == "" {
		opts.WorkspaceDir = "."
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var tfFiles []string
	err := filepath.WalkDir(opts.WorkspaceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".terraform" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".tf") {
			tfFiles = append(tfFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking workspace %s: %w", opts.WorkspaceDir, err)
	}

	fileCh := make(chan string, len(tfFiles))
	for _, f := range tfFiles {
		fileCh <- f
	}
	close(fileCh)

	var (
		mu         sync.Mutex
		candidates []CandidateRecord
		wg         sync.WaitGroup
		firstErr   error
	)

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				parsed, scanErr := parseHCLFile(path)
				mu.Lock()
				if scanErr != nil && firstErr == nil {
					firstErr = scanErr
				}
				candidates = append(candidates, parsed...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		plan     correlator.PlanJSON
		usedPlan bool
	)

	planPath := opts.PlanJSONPath
	if planPath == "" {
		candidatePlanPath := filepath.Join(opts.WorkspaceDir, "tfplan.json")
		if _, err := os.Stat(candidatePlanPath); err == nil {
			planPath = candidatePlanPath
		}
	}

	if planPath != "" {
		if planBytes, err := os.ReadFile(planPath); err == nil {
			if err := json.Unmarshal(planBytes, &plan); err == nil {
				usedPlan = true
			}
		}
	}

	candidatePlan := candidateRecordsToPlan(candidates)
	existingAddresses := make(map[string]bool)
	for _, rc := range plan.ResourceChanges {
		existingAddresses[rc.Address] = true
	}
	for _, rc := range candidatePlan.ResourceChanges {
		if !existingAddresses[rc.Address] {
			plan.ResourceChanges = append(plan.ResourceChanges, rc)
		}
	}

	evalRes, err := correlator.AnalyzePlan(&plan, opts.Prober)
	if err != nil {
		return nil, fmt.Errorf("evaluating plan: %w", err)
	}
	findings := evalRes.Findings
	evaluatedCount := evalRes.TotalModifiedRecords

	candByAddress := make(map[string]CandidateRecord)
	candByFQDN := make(map[string]CandidateRecord)
	for _, c := range candidates {
		addr := fmt.Sprintf("%s.%s", c.Provider, c.ResourceName)
		candByAddress[addr] = c
		switch c.Provider {
		case "aws_route53":
			candByAddress[fmt.Sprintf("aws_route53_record.%s", c.ResourceName)] = c
		case "cloudflare":
			candByAddress[fmt.Sprintf("cloudflare_record.%s", c.ResourceName)] = c
		case "azure_dns":
			candByAddress[fmt.Sprintf("azurerm_dns_cname_record.%s", c.ResourceName)] = c
		case "gcp_dns":
			candByAddress[fmt.Sprintf("google_dns_record_set.%s", c.ResourceName)] = c
		}
		if c.Name != "" {
			candByFQDN[correlator.NormalizeDomain(c.Name)] = c
		}
	}

	for i := range findings {
		if c, ok := candByAddress[findings[i].Address]; ok {
			findings[i].SourceFile = c.FilePath
			findings[i].StartLine = c.LineNumber
		} else if c, ok := candByFQDN[findings[i].FQDN]; ok {
			findings[i].SourceFile = c.FilePath
			findings[i].StartLine = c.LineNumber
		}
	}

	auditor := override.NewOverrideAuditor()
	overrideDir := opts.WorkspaceDir
	if opts.OverridePath != "" {
		overrideDir = opts.OverridePath
	}
	if err := auditor.ScanDirectory(overrideDir); err != nil {
		return nil, fmt.Errorf("in-code override validation failure: %w", err)
	}

	var activeFindings []correlator.Finding
	for _, f := range findings {
		ignored, _ := auditor.IsIgnored(f.RuleID, f.FQDN)
		if !ignored {
			activeFindings = append(activeFindings, f)
		}
	}

	return &LocalScanResult{
		EvaluatedRecords:     evaluatedCount,
		Findings:             activeFindings,
		IndeterminateTargets: evalRes.IndeterminateTargets,
		OverrideSnippets:     generateSnippets(activeFindings),
		UsedPlan:             usedPlan,
	}, nil
}

func candidateRecordsToPlan(candidates []CandidateRecord) *correlator.PlanJSON {
	plan := &correlator.PlanJSON{}
	for _, c := range candidates {
		if c.Provider == "aws_s3" || c.RecordType == "S3_BUCKET" {
			bucketName := c.Name
			if bucketName == "" {
				bucketName = c.ResourceName
			}
			plan.ResourceChanges = append(plan.ResourceChanges, correlator.ResourceChange{
				Address: fmt.Sprintf("aws_s3_bucket.%s", c.ResourceName),
				Type:    "aws_s3_bucket",
				Name:    c.ResourceName,
				Change: correlator.ChangeObj{
					Actions: []string{"no-op"},
					After: map[string]any{
						"bucket": bucketName,
					},
				},
			})
			continue
		}

		for _, target := range c.Targets {
			switch c.Provider {
			case "aws_route53":
				after := map[string]any{
					"name": c.Name,
					"type": c.RecordType,
				}
				if strings.EqualFold(c.RecordType, "CNAME") || c.RecordType == "" {
					after["type"] = "CNAME"
					after["records"] = []any{target}
				} else {
					after["alias"] = map[string]any{
						"dns_name": target,
					}
				}
				plan.ResourceChanges = append(plan.ResourceChanges, correlator.ResourceChange{
					Address: fmt.Sprintf("aws_route53_record.%s", c.ResourceName),
					Type:    "aws_route53_record",
					Name:    c.ResourceName,
					Change: correlator.ChangeObj{
						Actions: []string{"no-op"},
						After:   after,
					},
				})

			case "cloudflare":
				recType := c.RecordType
				if recType == "" {
					recType = "CNAME"
				}
				plan.ResourceChanges = append(plan.ResourceChanges, correlator.ResourceChange{
					Address: fmt.Sprintf("cloudflare_record.%s", c.ResourceName),
					Type:    "cloudflare_record",
					Name:    c.ResourceName,
					Change: correlator.ChangeObj{
						Actions: []string{"no-op"},
						After: map[string]any{
							"name":    c.Name,
							"type":    recType,
							"content": target,
						},
					},
				})

			case "azure_dns":
				plan.ResourceChanges = append(plan.ResourceChanges, correlator.ResourceChange{
					Address: fmt.Sprintf("azurerm_dns_cname_record.%s", c.ResourceName),
					Type:    "azurerm_dns_cname_record",
					Name:    c.ResourceName,
					Change: correlator.ChangeObj{
						Actions: []string{"no-op"},
						After: map[string]any{
							"name":      c.Name,
							"zone_name": c.ZoneName,
							"record":    target,
						},
					},
				})

			case "gcp_dns":
				name := c.Name
				if !strings.HasSuffix(name, ".") {
					name += "."
				}
				recType := c.RecordType
				if recType == "" {
					recType = "CNAME"
				}
				plan.ResourceChanges = append(plan.ResourceChanges, correlator.ResourceChange{
					Address: fmt.Sprintf("google_dns_record_set.%s", c.ResourceName),
					Type:    "google_dns_record_set",
					Name:    c.ResourceName,
					Change: correlator.ChangeObj{
						Actions: []string{"no-op"},
						After: map[string]any{
							"name":    name,
							"type":    recType,
							"rrdatas": []any{target},
						},
					},
				})
			}
		}
	}
	return plan
}

func parseHCLFile(path string) ([]CandidateRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var (
		results         []CandidateRecord
		current         *CandidateRecord
		braceDepth      int
		inRecords       bool
		inAlias         bool
		aliasBraceDepth int
		lineNum         int
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if current == nil {
			if provider, resName, ok := matchResourceHeader(line); ok {
				current = &CandidateRecord{
					Provider:     provider,
					ResourceName: resName,
					FilePath:     path,
					LineNumber:   lineNum,
				}
				braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
				if braceDepth <= 0 {
					braceDepth = 1
				}
			}
			continue
		}

		if aliasBlockRegex.MatchString(line) {
			inAlias = true
			aliasBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			if m := aliasTargetRegex.FindStringSubmatch(line); len(m) > 1 {
				current.Targets = append(current.Targets, m[1])
			}
		} else if inAlias {
			aliasBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if m := aliasTargetRegex.FindStringSubmatch(line); len(m) > 1 {
				current.Targets = append(current.Targets, m[1])
			}
			if aliasBraceDepth <= 0 {
				inAlias = false
			}
		} else {
			if m := nameAttrRegex.FindStringSubmatch(line); len(m) > 1 {
				current.Name = m[1]
			} else if m := zoneNameAttrRegex.FindStringSubmatch(line); len(m) > 1 {
				current.ZoneName = m[1]
			} else if m := typeAttrRegex.FindStringSubmatch(line); len(m) > 1 {
				current.RecordType = strings.ToUpper(m[1])
			} else if m := bucketAttrRegex.FindStringSubmatch(line); len(m) > 1 {
				current.Name = m[1]
				current.RecordType = "S3_BUCKET"
			} else if m := recordAttrRegex.FindStringSubmatch(line); len(m) > 1 {
				current.Targets = append(current.Targets, m[1])
			}
		}

		if (strings.Contains(trimmed, "records") || strings.Contains(trimmed, "rrdatas")) && strings.Contains(trimmed, "[") {
			inRecords = true
		}
		if inRecords {
			matches := listItemRegex.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) > 1 && m[1] != "records" && m[1] != "rrdatas" {
					current.Targets = append(current.Targets, m[1])
				}
			}
			if strings.Contains(trimmed, "]") {
				inRecords = false
			}
		}

		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if braceDepth <= 0 {
			results = append(results, *current)
			current = nil
			inRecords = false
			inAlias = false
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s: %w", path, err)
	}

	return results, nil
}

func matchResourceHeader(line string) (provider string, resourceName string, ok bool) {
	if m := route53RecordRegex.FindStringSubmatch(line); len(m) > 1 {
		return "aws_route53", m[1], true
	}
	if m := cloudflareRecordRegex.FindStringSubmatch(line); len(m) > 1 {
		return "cloudflare", m[1], true
	}
	if m := azureRecordRegex.FindStringSubmatch(line); len(m) > 1 {
		return "azure_dns", m[1], true
	}
	if m := gcpRecordRegex.FindStringSubmatch(line); len(m) > 1 {
		return "gcp_dns", m[1], true
	}
	if m := s3BucketRegex.FindStringSubmatch(line); len(m) > 1 {
		return "aws_s3", m[1], true
	}
	return "", "", false
}

func generateSnippets(findings []correlator.Finding) map[string]string {
	snippets := make(map[string]string)
	expiryDate := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	user := "@developer"

	// Only query git config --global so local .git/config files in scanned directories are never read or evaluated
	if out, err := exec.Command("git", "config", "--global", "user.email").Output(); err == nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" && strings.Contains(trimmed, "@") {
			parts := strings.Split(trimmed, "@")
			user = "@" + strings.ToLower(parts[0])
		}
	}
	if user == "@developer" {
		if out, err := exec.Command("git", "config", "--global", "user.name").Output(); err == nil {
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
	}

	for _, f := range findings {
		snippets[f.FQDN] = fmt.Sprintf(
			"# subdomainwatch-ignore: %s domain=%s expires=%s approver=%s reason=\"Accepted pre-commit risk\"",
			f.RuleID, f.FQDN, expiryDate, user,
		)
	}
	return snippets
}
