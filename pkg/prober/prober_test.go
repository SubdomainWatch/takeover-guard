package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadOfflineSignatures(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create fingerprint engine: %v", err)
	}

	if engine.Bundle == nil {
		t.Fatal("expected non-nil bundle")
	}

	if len(engine.Bundle.Signatures) < 30 {
		t.Errorf("expected at least 30 provider signatures, got %d", len(engine.Bundle.Signatures))
	}

	// Verify AWS S3, GitHub Pages, Heroku exist
	foundS3 := false
	foundGH := false
	foundHeroku := false

	for _, sig := range engine.Bundle.Signatures {
		switch sig.Provider {
		case "AWS S3":
			foundS3 = true
		case "GitHub Pages":
			foundGH = true
		case "Heroku":
			foundHeroku = true
		}
	}

	if !foundS3 || !foundGH || !foundHeroku {
		t.Errorf("missing core providers: s3=%v, gh=%v, heroku=%v", foundS3, foundGH, foundHeroku)
	}
}

func TestIsCloudProviderTarget(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create fingerprint engine: %v", err)
	}

	prober := NewProber(engine)

	tests := []struct {
		target   string
		expected bool
	}{
		{"my-bucket.s3.amazonaws.com", true},
		{"sub.s3-website-us-east-1.amazonaws.com", true},
		{"my-org.github.io", true},
		{"app.herokuapp.com", true},
		{"app.herokudns.com", true},
		{"site.surge.sh", true},
		{"google.com", false},
		{"internal.acme.corp", false},
		{"", false},
	}

	for _, tc := range tests {
		got := prober.IsCloudProviderTarget(tc.target)
		if got != tc.expected {
			t.Errorf("target %q: expected %v, got %v", tc.target, tc.expected, got)
		}
	}
}

func TestProbeClaimabilityMatch(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test server simulating AWS S3 NoSuchBucket
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>")
	}))
	defer ts.Close()

	prober := NewProber(engine)
	prober.SetCustomTransport(ts.Client().Transport)

	// Inject custom test transport mapping test host to mock server URL
	vulnerable, sev, rem := prober.ProbeClaimability(ts.Listener.Addr().String(), "acme-test.s3.amazonaws.com")
	if !vulnerable {
		t.Errorf("expected vulnerable = true for S3 NoSuchBucket mock, got %v", vulnerable)
	}
	if sev != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", sev)
	}
	if rem == "" {
		t.Errorf("expected non-empty remediation guide")
	}
}
