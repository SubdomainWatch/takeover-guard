package dnsresolver

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	client    *dns.Client
	sem       chan struct{} // 20 concurrent goroutines (§7)
	timeout   time.Duration
	defaultNS []string

	cbLock              sync.Mutex
	consecutiveTimeouts int
	timedOutTargets     []string
	isTripped           bool
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		client: &dns.Client{
			Timeout: 2500 * time.Millisecond,
			Net:     "udp",
		},
		sem:       make(chan struct{}, 20), // Bounded at 20 goroutines (§7)
		timeout:   2500 * time.Millisecond,
		defaultNS: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
	}
}

// RandomizeCase0x20 applies DNS 0x20 bit case randomization (§2.2)
func RandomizeCase0x20(domain string) string {
	var sb strings.Builder
	for _, ch := range domain {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			n, err := rand.Int(rand.Reader, big.NewInt(2))
			if err == nil && n.Int64() == 1 {
				sb.WriteString(strings.ToUpper(string(ch)))
			} else {
				sb.WriteString(strings.ToLower(string(ch)))
			}
		} else {
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

// ResolveCNAME performs authoritative DNS query with 0x20 case randomization
func (r *DNSResolver) ResolveCNAME(domain string) ([]string, error) {
	r.cbLock.Lock()
	if r.isTripped {
		r.cbLock.Unlock()
		return nil, fmt.Errorf("CIRCUIT_BREAKER_TRIP: Security gate aborted. 5 consecutive DNS timeouts detected on targets: %v. Manual security review required", r.timedOutTargets)
	}
	r.cbLock.Unlock()

	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	// Apply 0x20 bit randomization
	randomized := RandomizeCase0x20(strings.TrimSuffix(domain, ".")) + "."

	m := new(dns.Msg)
	m.SetQuestion(randomized, dns.TypeCNAME)
	m.RecursionDesired = true
	m.Id = dns.Id()

	var lastErr error
	var resp *dns.Msg

	for _, ns := range r.defaultNS {
		in, _, err := r.client.Exchange(m, ns)
		if err != nil {
			lastErr = err
			continue
		}
		resp = in
		break
	}

	if resp == nil {
		r.recordTimeout(domain)
		return nil, fmt.Errorf("dns query timeout for %s: %w", domain, lastErr)
	}

	// Successful query resets consecutive timeout counter
	r.recordSuccess()

	// Verify 0x20 casing in answer question (§2.2)
	if len(resp.Question) > 0 {
		respQ := resp.Question[0].Name
		if !strings.EqualFold(respQ, randomized) {
			return nil, fmt.Errorf("dns 0x20 case validation failed: query %s != resp %s", randomized, respQ)
		}
	}

	var cnames []string
	for _, ans := range resp.Answer {
		if cnameRecord, ok := ans.(*dns.CNAME); ok {
			cnames = append(cnames, strings.TrimSuffix(cnameRecord.Target, "."))
		}
	}

	return cnames, nil
}

// Circuit breaker tracking (§7 & §3.3)
func (r *DNSResolver) RecordTimeout(target string) {
	r.recordTimeout(target)
}

func (r *DNSResolver) RecordSuccess() {
	r.recordSuccess()
}

func (r *DNSResolver) recordTimeout(target string) {
	r.cbLock.Lock()
	defer r.cbLock.Unlock()

	r.consecutiveTimeouts++
	r.timedOutTargets = append(r.timedOutTargets, target)

	if r.consecutiveTimeouts >= 5 {
		r.isTripped = true
	}
}

func (r *DNSResolver) recordSuccess() {
	r.cbLock.Lock()
	defer r.cbLock.Unlock()

	r.consecutiveTimeouts = 0
	r.timedOutTargets = nil
}

func (r *DNSResolver) IsCircuitBreakerTripped() (bool, []string) {
	r.cbLock.Lock()
	defer r.cbLock.Unlock()
	return r.isTripped, r.timedOutTargets
}

