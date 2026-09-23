package override

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	ignoreRegex = regexp.MustCompile(`(?i)^\s*(?:#|//)\s*subdomainwatch-ignore:\s*([A-Za-z0-9*-]+)\s+domain=([^\s]+)\s+expires=([^\s]+)\s+approver=([^\s]+)\s+reason="([^"]+)"`)
	resourceRegex = regexp.MustCompile(`(?i)^\s*resource\s+"([^"]+)"\s+"([^"]+)"`)
)

type IgnoreEntry struct {
	RuleID    string
	Domain    string
	Expires   time.Time
	Approver  string
	Reason    string
	LineNum   int
	FilePath  string
	TargetRes string
}

type OverrideAuditor struct {
	overrides map[string]*IgnoreEntry // domain -> entry
	now       time.Time
}

func NewOverrideAuditor() *OverrideAuditor {
	return &OverrideAuditor{
		overrides: make(map[string]*IgnoreEntry),
		now:       time.Now().UTC(),
	}
}

// SetNow allows mocking time in tests
func (a *OverrideAuditor) SetNow(t time.Time) {
	a.now = t
}

// ScanFile scans a Terraform file for line N-1 comments preceding resource blocks (§9.1 & §3.4)
func (a *OverrideAuditor) ScanFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	var lastCommentLine int
	var pendingEntry *IgnoreEntry

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Check for ignore comment
		if match := ignoreRegex.FindStringSubmatch(line); match != nil {
			ruleID := match[1]
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(match[2]), "."))
			expiresStr := match[3]
			approver := match[4]
			reason := match[5]

			if ruleID == "*" {
				return fmt.Errorf("%s:%d: Wildcard '*' rule IDs are not permitted. Specify explicit rule IDs (e.g., SW-G-001)", filePath, lineNum)
			}

			expiresDate, err := time.Parse("2006-01-02", expiresStr)
			if err != nil {
				return fmt.Errorf("%s:%d: invalid expires date format '%s' (expected YYYY-MM-DD)", filePath, lineNum, expiresStr)
			}

			// Validate expiration policy (§9.2 & Gap 3 / P1-4):
			// If expires <= today: log warning and do NOT suppress findings, but do NOT crash build
			if !expiresDate.After(a.now) {
				fmt.Fprintf(os.Stderr, "⚠ Override for %s expired on %s (file %s:%d) — override will not suppress findings\n", domain, expiresStr, filePath, lineNum)
				continue
			}

			// If expires > today + 90 days: fail build
			maxExpiry := a.now.AddDate(0, 0, 90)
			if expiresDate.After(maxExpiry) {
				return fmt.Errorf("ERROR: Override for %s has expiration date %s exceeding the maximum 90-day policy (file %s:%d)", domain, expiresStr, filePath, lineNum)
			}

			pendingEntry = &IgnoreEntry{
				RuleID:   ruleID,
				Domain:   domain,
				Expires:  expiresDate,
				Approver: approver,
				Reason:   reason,
				LineNum:  lineNum,
				FilePath: filePath,
			}
			lastCommentLine = lineNum
			continue
		}

		// Check for resource block
		if resMatch := resourceRegex.FindStringSubmatch(line); resMatch != nil {
			if pendingEntry != nil {
				// Line N-1 Proximity Binding (§9.1 & Refinement §3.4)
				// Must be line N-1 or N-2 (allowing 0 to 1 blank lines)
				diff := lineNum - lastCommentLine
				if diff > 2 {
					return fmt.Errorf("%s:%d: Detached # subdomainwatch-ignore comment at line %d rejected. Must be on line directly preceding resource block", filePath, lineNum, lastCommentLine)
				}

				resType := resMatch[1]
				resName := resMatch[2]
				pendingEntry.TargetRes = fmt.Sprintf("%s.%s", resType, resName)

				a.overrides[pendingEntry.Domain] = pendingEntry
				pendingEntry = nil
			}
			continue
		}

		// If a non-blank, non-comment line appears before resource, invalidate pending ignore
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			if pendingEntry != nil {
				return fmt.Errorf("%s:%d: Detached # subdomainwatch-ignore comment at line %d rejected", filePath, lineNum, lastCommentLine)
			}
		}
	}

	if pendingEntry != nil {
		return fmt.Errorf("%s:%d: Detached # subdomainwatch-ignore comment at end of file without matching resource", filePath, pendingEntry.LineNum)
	}

	return scanner.Err()
}

// ScanDirectory walks a directory and scans all .tf files
func (a *OverrideAuditor) ScanDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tf") {
			if err := a.ScanFile(path); err != nil {
				return err
			}
		}
		return nil
	})
}

// IsIgnored checks if finding matches a valid active override
func (a *OverrideAuditor) IsIgnored(ruleID, fqdn string) (bool, *IgnoreEntry) {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	entry, exists := a.overrides[norm]
	if !exists {
		return false, nil
	}

	if strings.EqualFold(entry.RuleID, ruleID) {
		return true, entry
	}

	return false, nil
}
