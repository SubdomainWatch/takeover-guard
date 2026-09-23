package prober

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type WildcardBaseline struct {
	StatusCode int
	BodyHash   string
	BodyLen    int
}

type Prober struct {
	engine     *FingerprintEngine
	httpClient *http.Client
	httpSem    chan struct{} // Governs 10 concurrent HTTP clients (§7)

	wildcardLock  sync.RWMutex
	wildcardCache map[string]*WildcardBaseline
}

func isIPBlocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Cloud metadata (169.254.0.0/16, AWS/GCP/Azure)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}

func NewProber(engine *FingerprintEngine) *Prober {
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			var safeIP net.IP
			for _, ip := range ips {
				if isIPBlocked(ip) {
					return nil, fmt.Errorf("SSRF guard: refusing connection to %s (%s)", host, ip)
				}
				if safeIP == nil {
					safeIP = ip
				}
			}

			if safeIP == nil {
				return nil, fmt.Errorf("SSRF guard: no valid IP resolved for %s", host)
			}

			// Pin connection to the first validated safe IP to prevent DNS rebinding TOCTOU
			pinnedAddr := net.JoinHostPort(safeIP.String(), port)
			return dialer.DialContext(ctx, network, pinnedAddr)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 2 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second, // 3-second HTTP client timeout (§7)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Prober{
		engine:        engine,
		httpClient:    client,
		httpSem:       make(chan struct{}, 10), // Max 10 concurrent HTTP clients (§7)
		wildcardCache: make(map[string]*WildcardBaseline),
	}
}

// SetCustomTransport allows test harnesses or mocks to override the transport
func (p *Prober) SetCustomTransport(rt http.RoundTripper) {
	p.httpClient.Transport = rt
}

// IsCloudProviderTarget checks if a canonical target matches any known CNAME patterns from fingerprint database
func (p *Prober) IsCloudProviderTarget(target string) bool {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if p.engine == nil || p.engine.Bundle == nil {
		return false
	}

	for _, sig := range p.engine.Bundle.Signatures {
		for _, re := range sig.compiledPatterns {
			if re != nil && re.MatchString(norm) {
				return true
			}
		}
	}
	return false
}

// ProbeClaimability executes live multi-vector fingerprint probing (§5) with SSRF guard and wildcard suppression (§6.3)
func (p *Prober) ProbeClaimability(fqdn, target string) (bool, string, string) {
	normTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	normFQDN := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")

	// Find matching signatures
	var matchingSigs []Fingerprint
	for _, sig := range p.engine.Bundle.Signatures {
		for _, re := range sig.compiledPatterns {
			if re != nil && re.MatchString(normTarget) {
				matchingSigs = append(matchingSigs, sig)
				break
			}
		}
	}

	if len(matchingSigs) == 0 {
		return false, "", ""
	}

	// Wildcard Subdomain Probing Baseline Check (§6.3)
	apex := extractApex(normFQDN)
	baseline := p.getWildcardBaseline(apex)

	// Acquire HTTP semaphore
	p.httpSem <- struct{}{}
	defer func() { <-p.httpSem }()

	// Probe target endpoint using 16KB range request
	status, bodyStr, bodyHash, headers, err := p.executeSafeProbe(normFQDN)
	if err != nil {
		// Try target directly as fallback if fqdn not resolving
		status, bodyStr, bodyHash, headers, err = p.executeSafeProbe(normTarget)
		if err != nil {
			return false, "", ""
		}
	}

	// Wildcard suppression: if response matches the wildcard baseline profile, suppress alert
	if baseline != nil && baseline.StatusCode == status && baseline.BodyHash == bodyHash {
		return false, "", ""
	}

	// Multi-vector matching: status code + body tokens + headers
	for _, sig := range matchingSigs {
		statusMatches := false
		for _, code := range sig.HttpStatusCodes {
			if code == status {
				statusMatches = true
				break
			}
		}

		if !statusMatches && len(sig.HttpStatusCodes) > 0 {
			continue
		}

		tokenMatches := false
		for _, token := range sig.ResponseTokens {
			if strings.Contains(bodyStr, token) {
				tokenMatches = true
				break
			}
		}

		if tokenMatches {
			// Check response headers if required by signature
			headersMatch := true
			for hKey, hVal := range sig.ResponseHeaders {
				actualVal := headers.Get(hKey)
				if !strings.Contains(strings.ToLower(actualVal), strings.ToLower(hVal)) {
					headersMatch = false
					break
				}
			}

			if headersMatch {
				return true, sig.Severity, sig.RemediationGuide
			}
		}
	}

	return false, "", ""
}

func (p *Prober) executeSafeProbe(host string) (int, string, string, http.Header, error) {
	reqUrl := "http://" + host
	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return 0, "", "", nil, err
	}

	// Hardened safe headers: 16KB Range header to avoid reading massive payloads
	req.Header.Set("Range", "bytes=0-16383")
	req.Header.Set("User-Agent", "SubdomainWatch-Takeover-Guard/2.1.0")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, "", "", nil, err
	}
	defer resp.Body.Close()

	// Limit reader to 16KB
	lr := io.LimitReader(resp.Body, 16384)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return resp.StatusCode, "", "", resp.Header, err
	}

	h := sha256.Sum256(bodyBytes)
	bodyHash := hex.EncodeToString(h[:])

	return resp.StatusCode, string(bodyBytes), bodyHash, resp.Header, nil
}

// Wildcard baseline probing (§6.3)
func (p *Prober) getWildcardBaseline(apex string) *WildcardBaseline {
	if apex == "" {
		return nil
	}

	p.wildcardLock.RLock()
	baseline, exists := p.wildcardCache[apex]
	p.wildcardLock.RUnlock()
	if exists {
		return baseline
	}

	p.wildcardLock.Lock()
	defer p.wildcardLock.Unlock()

	// Double-check after lock
	if baseline, exists := p.wildcardCache[apex]; exists {
		return baseline
	}

	// Generate unguessable probe host: __sw_probe_<hex16>.<apex>
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	probeHost := fmt.Sprintf("__sw_probe_%s.%s", hex.EncodeToString(randBytes), apex)

	status, _, bodyHash, _, err := p.executeSafeProbe(probeHost)
	if err != nil {
		p.wildcardCache[apex] = nil
		return nil
	}

	b := &WildcardBaseline{
		StatusCode: status,
		BodyHash:   bodyHash,
	}
	p.wildcardCache[apex] = b
	return b
}

func extractApex(fqdn string) string {
	parts := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(parts) <= 2 {
		return fqdn
	}
	// Simple two-part TLD handling
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
