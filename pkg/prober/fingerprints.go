package prober

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//go:embed fingerprints_offline_v2.json
var embeddedOfflineSignatures []byte

// Dual-Key Ring (Ed25519 public keys) for cryptographic verification (§5.1)
const (
	CurrentPublicKeyHex  = "a7d9b935418b3df99f30b91e54ad36395b2ceee0e029c7b9e761994e43e2f57a"
	PreviousPublicKeyHex = "84f183756d538e12b70f08be92ceb65f3f4e3c15f9adca08e82ef478c92a9532"
)

type LiveStatus struct {
	IsVulnerable bool   `json:"is_vulnerable"`
	Severity     string `json:"severity"`
	Remediation  string `json:"remediation"`
	Provider     string `json:"provider"`
}

type Fingerprint struct {
	Provider         string            `json:"provider"`
	CnamePatterns    []string          `json:"cname_patterns"`
	HttpStatusCodes  []int             `json:"http_status_codes"`
	ResponseTokens   []string          `json:"response_tokens"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	Severity         string            `json:"severity"`
	RemediationGuide string            `json:"remediation_guide"`
	compiledPatterns []*regexp.Regexp
}

type FingerprintBundle struct {
	Version     string        `json:"version"`
	GeneratedAt string        `json:"generated_at"`
	Signatures  []Fingerprint `json:"signatures"`
}

type FingerprintEngine struct {
	Bundle      *FingerprintBundle
	IsAirGapped bool
}

func NewFingerprintEngine() (*FingerprintEngine, error) {
	bundle, err := LoadOfflineSignatures()
	if err != nil {
		return nil, fmt.Errorf("failed to load offline signatures: %w", err)
	}

	return &FingerprintEngine{
		Bundle:      bundle,
		IsAirGapped: true,
	}, nil
}

func LoadOfflineSignatures() (*FingerprintBundle, error) {
	var bundle FingerprintBundle
	if err := json.Unmarshal(embeddedOfflineSignatures, &bundle); err != nil {
		return nil, err
	}

	for i := range bundle.Signatures {
		sig := &bundle.Signatures[i]
		for _, pat := range sig.CnamePatterns {
			re, err := regexp.Compile("(?i)" + pat)
			if err == nil {
				sig.compiledPatterns = append(sig.compiledPatterns, re)
			}
		}
	}

	return &bundle, nil
}

// UpdateFromRemote attempts to download updated signatures and verify Ed25519 signature (§5.1).
// Falls back seamlessly to existing bundle on any error.
func (e *FingerprintEngine) UpdateFromRemote(url string) error {
	if url == "" {
		url = "https://signatures.subdomainwatch.com/fingerprints_v2.json"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network/proxy blocked or air-gapped: fallback gracefully
		return fmt.Errorf("remote signature fetch failed (using offline bundle): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote signatures returned HTTP %d", resp.StatusCode)
	}

	const maxBundleBytes = 8 << 20 // 8 MiB signed bundle ceiling
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxBundleBytes {
		return fmt.Errorf("remote bundle exceeds %d byte ceiling; rejected", maxBundleBytes)
	}

	sigHex := resp.Header.Get("X-Signature-Ed25519")
	if sigHex == "" {
		return fmt.Errorf("remote bundle rejected: missing X-Signature-Ed25519 header (possible MITM)")
	}
	if !verifyEd25519Signature(body, sigHex) {
		return fmt.Errorf("cryptographic signature verification failed for remote bundle")
	}

	var bundle FingerprintBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return err
	}

	for i := range bundle.Signatures {
		sig := &bundle.Signatures[i]
		for _, pat := range sig.CnamePatterns {
			re, err := regexp.Compile("(?i)" + pat)
			if err == nil {
				sig.compiledPatterns = append(sig.compiledPatterns, re)
			}
		}
	}

	e.Bundle = &bundle
	e.IsAirGapped = false
	return nil
}

func verifyEd25519Signature(data []byte, sigHex string) bool {
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}

	for _, keyHex := range []string{CurrentPublicKeyHex, PreviousPublicKeyHex} {
		pubKeyBytes, err := hex.DecodeString(keyHex)
		if err == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
			if ed25519.Verify(pubKeyBytes, data, sig) {
				return true
			}
		}
	}
	return false
}
