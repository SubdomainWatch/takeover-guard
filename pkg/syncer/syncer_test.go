package syncer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

func TestSyncTelemetry_StandaloneWhenNoKey(t *testing.T) {
	// Must return nil and make zero requests
	err := SyncTelemetry(context.Background(), "http://unreachable-host:9999", "", &SyncPayload{})
	if err != nil {
		t.Errorf("expected nil error for empty API key, got %v", err)
	}
}

func TestSyncTelemetry_Success(t *testing.T) {
	receivedAuth := ""
	receivedApiKey := ""
	var receivedPayload SyncPayload

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedApiKey = r.Header.Get("X-API-Key")
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true,"scan_id":"test-uuid"}`))
	}))
	defer ts.Close()

	payload := &SyncPayload{
		Repository: "acme/infra",
		Branch:     "main",
		CommitSHA:  "abcd1234",
		Mode:       "pre-merge",
		Status:     "failed",
		Findings: []correlator.Finding{
			{
				RuleID:   "SW-G-001",
				Severity: "CRITICAL",
				FQDN:     "staging.acme.com",
			},
		},
	}

	err := SyncTelemetry(context.Background(), ts.URL, "sw_guard_mockkey123", payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Bearer sw_guard_mockkey123" {
		t.Errorf("expected Bearer auth header, got %s", receivedAuth)
	}
	if receivedApiKey != "sw_guard_mockkey123" {
		t.Errorf("expected X-API-Key header, got %s", receivedApiKey)
	}
	if receivedPayload.Repository != "acme/infra" {
		t.Errorf("expected repo acme/infra, got %s", receivedPayload.Repository)
	}
}
