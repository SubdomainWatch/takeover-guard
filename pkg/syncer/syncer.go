package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

type OverridePayload struct {
	RuleID     string `json:"rule_id"`
	Domain     string `json:"domain"`
	Approver   string `json:"approver"`
	Reason     string `json:"reason"`
	ExpiresAt  string `json:"expires_at"`
	FilePath   string `json:"file_path,omitempty"`
	LineNumber int    `json:"line_number,omitempty"`
}

type SyncPayload struct {
	Repository           string               `json:"repository"`
	Branch               string               `json:"branch"`
	CommitSHA            string               `json:"commit_sha"`
	PRNumber             *int                 `json:"pr_number,omitempty"`
	Mode                 string               `json:"mode"`
	ToolVersion          string               `json:"tool_version"`
	Timestamp            string               `json:"timestamp"`
	Status               string               `json:"status"`
	TotalModifiedRecords int                  `json:"total_modified_records"`
	CriticalCount        int                  `json:"critical_count"`
	HighCount            int                  `json:"high_count"`
	WarningCount         int                  `json:"warning_count"`
	Findings             []correlator.Finding `json:"findings"`
	Overrides            []OverridePayload    `json:"overrides"`
}

type EnvironmentInfo struct {
	Repository string
	Branch     string
	CommitSHA  string
	PRNumber   *int
}

// DetectEnvironment extracts repository and CI context
func DetectEnvironment() EnvironmentInfo {
	info := EnvironmentInfo{
		Repository: "local/repository",
		Branch:     "main",
		CommitSHA:  "HEAD",
	}

	// 1. GitHub Actions Environment
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		info.Repository = repo
		if headRef := os.Getenv("GITHUB_HEAD_REF"); headRef != "" {
			info.Branch = headRef
		} else if refName := os.Getenv("GITHUB_REF_NAME"); refName != "" {
			info.Branch = refName
		}
		if sha := os.Getenv("GITHUB_SHA"); sha != "" {
			info.CommitSHA = sha
		}
		if eventPath := os.Getenv("GITHUB_EVENT_PATH"); eventPath != "" {
			if eventBytes, err := os.ReadFile(eventPath); err == nil {
				var eventObj struct {
					PullRequest struct {
						Number int `json:"number"`
					} `json:"pull_request"`
					Number int `json:"number"`
				}
				if err := json.Unmarshal(eventBytes, &eventObj); err == nil {
					if eventObj.PullRequest.Number > 0 {
						n := eventObj.PullRequest.Number
						info.PRNumber = &n
					} else if eventObj.Number > 0 {
						n := eventObj.Number
						info.PRNumber = &n
					}
				}
			}
		}
		return info
	}

	// 2. GitLab CI Environment
	if repo := os.Getenv("CI_PROJECT_PATH"); repo != "" {
		info.Repository = repo
		if branch := os.Getenv("CI_COMMIT_REF_NAME"); branch != "" {
			info.Branch = branch
		}
		if sha := os.Getenv("CI_COMMIT_SHA"); sha != "" {
			info.CommitSHA = sha
		}
		if mrIID := os.Getenv("CI_MERGE_REQUEST_IID"); mrIID != "" {
			if n, err := strconv.Atoi(mrIID); err == nil {
				info.PRNumber = &n
			}
		}
		return info
	}

	// 3. Fallback to local git CLI
	if out, err := exec.Command("git", "remote", "get-url", "origin").Output(); err == nil {
		remote := strings.TrimSpace(string(out))
		remote = strings.TrimSuffix(remote, ".git")
		parts := strings.Split(remote, "/")
		if len(parts) >= 2 {
			info.Repository = parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
	}
	if out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		b := strings.TrimSpace(string(out))
		if b != "" {
			info.Branch = b
		}
	}
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		if len(s) >= 8 {
			info.CommitSHA = s[:8]
		}
	}

	return info
}

// SyncTelemetry delivers scan telemetry to SubdomainWatch SaaS (§10 Phase 3).
// If apiKey is empty, Standalone Local Engine Mode is preserved.
func SyncTelemetry(ctx context.Context, syncURL, apiKey string, payload *SyncPayload) error {
	if apiKey == "" {
		// Standalone Local Engine Mode - zero outbound telemetry
		return nil
	}

	if syncURL == "" {
		syncURL = "https://subdomainwatch.com/api/guard/sync"
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to serialize telemetry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", syncURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create sync request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", "SubdomainWatch-Guard/2.1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Non-blocking fail-safe: log note without halting CI check
		fmt.Fprintf(os.Stderr, "ℹ SubdomainWatch SaaS sync skipped (network notice: %v)\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✔ Scan telemetry synced to SubdomainWatch Console: %s\n", payload.Repository)
	} else {
		fmt.Fprintf(os.Stderr, "ℹ SubdomainWatch SaaS sync returned HTTP %d\n", resp.StatusCode)
	}

	return nil
}
