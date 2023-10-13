package pkg

import (
	"errors"
	"github.com/bepass-org/dnsutils/internal/resolvers"
	"github.com/bepass-org/dnsutils/internal/statute"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Resolver struct {
	options  statute.ResolverOptions
	resolver statute.IResolver
	cache    statute.DefaultCache
	logger   statute.Logger
	hosts    statute.Hosts
}

func NewResolver(options ...Option) *Resolver {
	p := &Resolver{
		options: statute.ResolverOptions{
			UseIPv4:            false,
			UseIPv6:            false,
			SearchList:         nil,
			Ndots:              0,
			Strategy:           "",
			Prefer:             "",
			Timeout:            0,
			InsecureSkipVerify: false,
			TLSHostname:        "",
		},
		cache:  statute.DefaultCache{},
		logger: statute.DefaultLogger{},
		hosts:  statute.Hosts{},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

type Option func(*Resolver)

func WithUseIPv4(useIPv4 bool) Option {
	return func(r *Resolver) {
		r.options.UseIPv4 = useIPv4
	}
}

func WithUseIPv6(useIPv6 bool) Option {
	return func(r *Resolver) {
		r.options.UseIPv6 = useIPv6
	}
}

func WithSearchList(searchList []string) Option {
	return func(r *Resolver) {
		r.options.SearchList = searchList
	}
}

func WithNdots(ndots int) Option {
	return func(r *Resolver) {
		r.options.Ndots = ndots
	}
}

func WithPrefer(prefer string) Option {
	return func(r *Resolver) {
		r.options.Prefer = prefer
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) {
		r.options.Timeout = timeout
	}
}

func WithInsecureSkipVerify(insecureSkipVerify bool) Option {
	return func(r *Resolver) {
		r.options.InsecureSkipVerify = insecureSkipVerify
	}
}

func WithTLSHostname(tlsHostname string) Option {
	return func(r *Resolver) {
		r.options.TLSHostname = tlsHostname
	}
}

func WithHost(domain string, ips []string) Option {
	return func(r *Resolver) {
		r.hosts[domain] = ips
	}
}

func (r *Resolver) SetDNSServer(address string) error {
	nsSrvType := statute.GetDNSType(address)
	var err error
	switch nsSrvType {
	case "udp":
		r.logger.Debug("initiating UDP resolver")
		r.resolver, err = resolvers.NewClassicResolver(address,
			resolvers.ClassicResolverOpts{
				UseTCP: false,
				UseTLS: false,
			}, r.options)
	case "tcp":
		r.logger.Debug("initiating TCP resolver")
		r.resolver, err = resolvers.NewClassicResolver(address,
			resolvers.ClassicResolverOpts{
				UseTCP: true,
				UseTLS: false,
			}, r.options)
	case "dot":
		r.logger.Debug("initiating DOT resolver")
		r.resolver, err = resolvers.NewClassicResolver(address,
			resolvers.ClassicResolverOpts{
				UseTCP: true,
				UseTLS: true,
			}, r.options)
	case "doh":
		r.logger.Debug("initiating DOH resolver")
		r.resolver, err = resolvers.NewDOHResolver(address, r.options)
	case "crypt":
		r.logger.Debug("initiating DNSCrypt resolver")
		r.resolver, err = resolvers.NewDNSCryptResolver(address,
			resolvers.DNSCryptResolverOpts{
				UseTCP: true,
			}, r.options)
	default:
		if strings.ToLower(nsSrvType) != "system" {
			err = errors.New("unknown dns server type! using default system resolver as fallback")
		}
		r.logger.Debug("initiating system resolver")
		r.resolver, err = resolvers.NewSystemResolver(r.options)
	}
	return err
}

// Resolve resolves the FQDN to an IP address using the specified resolution mechanism.
func (r *Resolver) Resolve(fqdn string) ([]string, error) {
	// CheckHosts checks if a given domain exists in the local resolver's hosts file
	// and returns the corresponding IP address if found, or an empty string if not.
	if ips, ok := r.hosts[fqdn]; ok {
		return ips, nil
	}

	// Ensure fqdn ends with a period
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	// Check the cache for fqdn
	if cachedValue, _ := r.cache.Get(fqdn); cachedValue != nil {
		r.logger.Debug("using cached value for %s", fqdn)
		return cachedValue.([]string), nil
	}

	question := dns.Question{
		Name:   fqdn,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	response, err := r.resolver.Lookup(question)
	if err != nil {
		return nil, err
	}
	r.logger.Debug("resolved %s to %s", fqdn, response.Answers[0].Address)
	if response.Answers[0].Type == "CNAME" {
		ip, err := r.Resolve(response.Answers[0].Address)
		if err != nil {
			return nil, err
		}
		r.cache.Set(fqdn, ip)
		return ip, nil
	}
	var ips []string
	for _, answer := range response.Answers {
		ips = append(ips, answer.Address)
	}
	r.cache.Set(fqdn, ips)
	return ips, nil
}
