package statute

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

// IResolver implements the configuration for a DNS
// Client. Different types of providers can load
// a DNS IResolver satisfying this interface.
type IResolver interface {
	Lookup(dns.Question) (Response, error)
}

// GetDNSType parse dns server uri returns the type of DNS server
// based on its URI, handling common misspellings and case variations.
func GetDNSType(uri string) string {
	normalized := strings.ToLower(uri)

	if strings.HasPrefix(normalized, "udp://") {
		return "udp"
	}
	if strings.HasPrefix(normalized, "tcp://") {
		return "tcp"
	}
	if strings.HasPrefix(normalized, "tls://") {
		return "tls"
	}
	if strings.HasPrefix(normalized, "https://") {
		return "doh"
	}
	if strings.HasPrefix(normalized, "sdns://") {
		return "crypt"
	}
	return "unknown"
}

// Response represents a custom output format
// for DNS queries. It wraps metadata about the DNS query
// and the DNS Answer as well.
type Response struct {
	Answers     []Answer    `json:"answers"`
	Authorities []Authority `json:"authorities"`
	Questions   []Question  `json:"questions"`
}

type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type Answer struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Class      string `json:"class"`
	TTL        string `json:"ttl"`
	Address    string `json:"address"`
	Status     string `json:"status"`
	RTT        string `json:"rtt"`
	Nameserver string `json:"nameserver"`
}

type Authority struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Class      string `json:"class"`
	TTL        string `json:"ttl"`
	MName      string `json:"mname"`
	Status     string `json:"status"`
	RTT        string `json:"rtt"`
	Nameserver string `json:"nameserver"`
}

// ResolverOptions represent a set of common options
// to configure a IResolver.
type ResolverOptions struct {
	UseIPv4            bool
	UseIPv6            bool
	SearchList         []string
	Ndots              int
	Strategy           string
	Prefer             string
	Timeout            time.Duration
	InsecureSkipVerify bool
	TLSHostname        string
}

// Hosts represents a domain-to-IP mapping entry in the local hosts file.
type Hosts map[string][]string
