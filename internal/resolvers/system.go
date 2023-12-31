package resolvers

import (
	"fmt"
	"github.com/bepass-org/dnsutils/internal/statute"
	"github.com/miekg/dns"
	"net"
)

// SystemResolver represents the config options for setting up a IResolver.
type SystemResolver struct {
	defaultTTL string
	opts       statute.ResolverOptions
}

// SystemResolverOpts holds options for setting up a System resolver.
type SystemResolverOpts struct{}

// NewSystemResolver accepts a list of nameservers and configures a DNS resolver.
func NewSystemResolver(resolverOpts statute.ResolverOptions) (statute.IResolver, error) {
	return &SystemResolver{
		defaultTTL: string(rune(statute.DefaultTTL)),
		opts:       resolverOpts,
	}, nil
}

// Lookup takes a dns.Question and sends them to DNS Server.
func (r *SystemResolver) Lookup(question dns.Question) (statute.Response, error) {
	var rsp statute.Response
	ips, err := net.LookupIP(question.Name)
	if err != nil {
		return rsp, err
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4Addresses []net.IP
	var ipv6Addresses []net.IP

	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4Addresses = append(ipv4Addresses, ip)
		} else {
			ipv6Addresses = append(ipv6Addresses, ip)
		}
	}

	// Print preferred IP version (e.g., IPv4)
	if len(ipv4Addresses) > 0 && r.opts.Prefer == "ipv4" {
		rsp.Answers = []statute.Answer{
			{
				Name:       question.Name,
				Type:       "A",
				Class:      "IN",         // Set to IN for Internet class
				TTL:        r.defaultTTL, // Set TTL to 1 hour (in seconds)
				Address:    ipv4Addresses[0].String(),
				Status:     "Success",
				RTT:        "N/A",
				Nameserver: "System IResolver",
			},
		}
	} else if len(ipv6Addresses) > 0 && r.opts.Prefer == "ipv4" {
		ipv6Answers := make([]statute.Answer, len(ipv6Addresses))
		for i, ip := range ipv6Addresses {
			ipv6Answers[i] = statute.Answer{
				Name:       question.Name,
				Type:       "AAAA",
				Class:      "IN",         // Set to IN for Internet class
				TTL:        r.defaultTTL, // Set TTL to 1 hour (in seconds)
				Address:    ip.String(),
				Status:     "Success",
				RTT:        "N/A",
				Nameserver: "System IResolver",
			}
		}
		rsp.Answers = append(rsp.Answers, ipv6Answers...)
	} else {
		fmt.Println("No IP addresses found.")
	}

	return rsp, nil
}
