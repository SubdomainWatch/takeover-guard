package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	// Also verify ProbeClaimabilityDetailed directly
	status, detailedSev, _, _ := prober.ProbeClaimabilityDetailed(ts.Listener.Addr().String(), "acme-test.s3.amazonaws.com")
	if status != "CONFIRMED" {
		t.Errorf("expected status CONFIRMED, got %s", status)
	}
	if detailedSev != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", detailedSev)
	}
}

func TestProbeClaimabilityClean(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Active valid site, status 200, no takeover fingerprint tokens
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><body>Welcome to Acme Corp Official Production Portal</body></html>")
	}))
	defer ts.Close()

	prober := NewProber(engine)
	prober.SetCustomTransport(ts.Client().Transport)

	status, _, _, errReason := prober.ProbeClaimabilityDetailed(ts.Listener.Addr().String(), "acme-test.s3.amazonaws.com")
	if status != "CLEAN" {
		t.Errorf("expected status CLEAN for active production site, got %s (err: %s)", status, errReason)
	}
}

type mockFailingTransport struct {
	err error
}

func (m *mockFailingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, m.err
}

func TestProbeClaimabilityIndeterminateOnTimeout(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	prober := NewProber(engine)
	// Inject a transport that simulates a connection timeout / i/o timeout
	prober.SetCustomTransport(&mockFailingTransport{
		err: fmt.Errorf("dial tcp 192.0.2.1:80: i/o timeout"),
	})

	status, _, _, errReason := prober.ProbeClaimabilityDetailed("timeout.example.com", "app.herokuapp.com")
	if status != "INDETERMINATE" {
		t.Errorf("expected status INDETERMINATE on transport timeout, got %s", status)
	}
	if errReason == "" {
		t.Errorf("expected non-empty diagnostic error reason for indeterminate probe")
	}

	// Legacy ProbeClaimability must report false (not confirmed vulnerable)
	isVuln, _, _ := prober.ProbeClaimability("timeout.example.com", "app.herokuapp.com")
	if isVuln {
		t.Errorf("expected isVuln = false for indeterminate probe, got true")
	}
}

func TestProberProxyIsNil(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	p := NewProber(engine)
	transport, ok := p.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", p.httpClient.Transport)
	}

	// Verify Proxy is strictly nil to prevent proxy environment variables from bypassing IP pinning SSRF checks
	if transport.Proxy != nil {
		t.Errorf("expected transport.Proxy to be nil, but got non-nil function")
	}

	// Verify timeouts: 3s client timeout, 2s dial / TLS timeouts
	if p.httpClient.Timeout != 3*time.Second {
		t.Errorf("expected httpClient.Timeout = 3s, got %v", p.httpClient.Timeout)
	}
	if transport.TLSHandshakeTimeout != 2*time.Second {
		t.Errorf("expected TLSHandshakeTimeout = 2s, got %v", transport.TLSHandshakeTimeout)
	}
}

func TestUpdateFromRemote_RejectsUnsignedAndTamperedBundles(t *testing.T) {
	eng, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("NewFingerprintEngine failed: %v", err)
	}

	// 1. Missing X-Signature-Ed25519 header must be rejected (MITM protection)
	unsignedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedOfflineSignatures)
	}))
	defer unsignedSrv.Close()

	if err := eng.UpdateFromRemote(unsignedSrv.URL); err == nil || !strings.Contains(err.Error(), "missing X-Signature-Ed25519") {
		t.Fatalf("expected missing signature error, got: %v", err)
	}
	if !eng.IsAirGapped {
		t.Errorf("expected engine to remain in offline air-gapped state after rejected update")
	}

	// 2. Forged Ed25519 signature must be rejected
	forgedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Signature-Ed25519", strings.Repeat("aa", 64))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedOfflineSignatures)
	}))
	defer forgedSrv.Close()

	if err := eng.UpdateFromRemote(forgedSrv.URL); err == nil || !strings.Contains(err.Error(), "cryptographic signature verification failed") {
		t.Fatalf("expected signature verification failure, got: %v", err)
	}
}

