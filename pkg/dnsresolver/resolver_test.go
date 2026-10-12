package dnsresolver

import (
	"strings"
	"testing"
)

func TestRandomizeCase0x20(t *testing.T) {
	domain := "staging.acme.com"
	randomized := RandomizeCase0x20(domain)

	if !strings.EqualFold(randomized, domain) {
		t.Errorf("expected case-insensitive equality: %s vs %s", domain, randomized)
	}

	if len(randomized) != len(domain) {
		t.Errorf("length mismatch: %d vs %d", len(randomized), len(domain))
	}
}

func TestCircuitBreakerHardFail(t *testing.T) {
	resolver := NewDNSResolver()

	targets := []string{
		"target1.acme.internal",
		"target2.acme.internal",
		"target3.acme.internal",
		"target4.acme.internal",
		"target5.acme.internal",
	}

	for _, target := range targets {
		resolver.recordTimeout(target)
	}

	tripped, timedOut := resolver.IsCircuitBreakerTripped()
	if !tripped {
		t.Fatal("expected circuit breaker to be tripped after 5 consecutive timeouts")
	}

	if len(timedOut) != 5 {
		t.Errorf("expected 5 timed out targets recorded, got %d", len(timedOut))
	}

	// Verify next query aborts with CIRCUIT_BREAKER_TRIP error
	_, err := resolver.ResolveCNAME("any.domain.com")
	if err == nil || !strings.Contains(err.Error(), "CIRCUIT_BREAKER_TRIP") {
		t.Errorf("expected CIRCUIT_BREAKER_TRIP error, got: %v", err)
	}
}
