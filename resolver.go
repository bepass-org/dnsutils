package dnsutils

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bepass-org/dnsutils/internal/dialer"
	"github.com/bepass-org/dnsutils/internal/resolvers"
	"github.com/bepass-org/dnsutils/internal/statute"
	"github.com/miekg/dns"
)

// Resolver handles DNS lookups and caching
type Resolver struct {
	options  statute.ResolverOptions
	resolver statute.IResolver
	cache    statute.DefaultCache
	logger   statute.Logger
	hosts    statute.Hosts
}

// NewResolver creates a new Resolver with default options
// Options can be provided to customize the resolver
func NewResolver(options ...Option) *Resolver {

	// Create resolver with default options
	p := &Resolver{
		options: statute.ResolverOptions{
			UseIPv4:            false,
			UseIPv6:            false,
			SearchList:         nil,
			Ndots:              1,
			Prefer:             "",
			Timeout:            1 * time.Minute,
			InsecureSkipVerify: true,
			TLSHostname:        "",
			Logger:             statute.DefaultLogger{},
			Dialer:             &dialer.AppDialer{},
			TLSDialer:          &dialer.AppTLSDialer{},
			RawDialerFunc:      statute.DefaultDialerFunc,
			TLSDialerFunc:      statute.DefaultTLSDialerFunc,
			HttpClient:         statute.DefaultHTTPClient(nil, nil),
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

func WithTLSHostname(tlsHostname string) Option {
	return func(r *Resolver) {
		r.options.TLSHostname = tlsHostname
	}
}

func WithDialer(d dialer.TDialerFunc) Option {
	return func(r *Resolver) {
		r.options.RawDialerFunc = d
		r.options.HttpClient = statute.DefaultHTTPClient(r.options.RawDialerFunc, r.options.TLSDialerFunc)
		dialer.RawDialFunc = d
		r.options.Dialer = &dialer.AppDialer{Timeout: r.options.Timeout}
	}
}

func WithTLSDialer(t dialer.TDialerFunc) Option {
	return func(r *Resolver) {
		r.options.TLSDialerFunc = t
		r.options.HttpClient = statute.DefaultHTTPClient(r.options.RawDialerFunc, r.options.TLSDialerFunc)
		dialer.TLSDialFunc = t
		r.options.TLSDialer = &dialer.AppTLSDialer{Timeout: r.options.Timeout}
	}
}

func WithHttpClient(client *http.Client) Option {
	return func(r *Resolver) {
		r.options.HttpClient = client
	}
}

func WithLogger(logger statute.Logger) Option {
	return func(r *Resolver) {
		r.options.Logger = logger
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
		r.logger.Debug("initiating system resolver")
		r.resolver, err = resolvers.NewSystemResolver(r.options)
		if nsSrvType == "unknown" {
			r.logger.Error("unknown dns server type! using default system resolver as fallback")
		}
	}
	return err
}

// LookupIP resolves the FQDN to an IP address using the specified resolution mechanism.
func (r *Resolver) LookupIP(fqdn string) ([]string, error) {
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

	if len(response.Answers) == 0 {
		return nil, errors.New("no answers found")
	}

	r.logger.Debug("resolved %s to %s", fqdn, response.Answers[0].Address)
	if response.Answers[0].Type == "CNAME" {
		ip, err := r.LookupIP(response.Answers[0].Address)
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
