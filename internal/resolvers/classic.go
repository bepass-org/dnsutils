package resolvers

import (
	"crypto/tls"
	"github.com/bepass-org/dnsutils/internal/statute"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ClassicResolver represents the config options for setting up a IResolver.
type ClassicResolver struct {
	client *dns.Client
	server string
	opts   statute.ResolverOptions
}

// ClassicResolverOpts holds options for setting up a Classic resolver.
type ClassicResolverOpts struct {
	UseTLS bool
	UseTCP bool
}

// NewClassicResolver accepts a list of nameservers and configures a DNS resolver.
func NewClassicResolver(server string, classicOpts ClassicResolverOpts, resolverOpts statute.ResolverOptions) (statute.IResolver, error) {
	net := "udp"
	client := &dns.Client{
		Timeout: resolverOpts.Timeout,
		Net:     "udp",
	}

	if classicOpts.UseTCP {
		net = "tcp"
	}

	if resolverOpts.UseIPv4 {
		net = net + "4"
	}
	if resolverOpts.UseIPv6 {
		net = net + "6"
	}

	// if the both use ipv4 and ipv6, then net will be just udp or tcp
	net = strings.Replace(net, "46", "", -1)

	if classicOpts.UseTLS {
		net = net + "-tls"
		// Provide extra TLS config for doing/skipping hostname verification.
		client.TLSConfig = &tls.Config{
			ServerName:         resolverOpts.TLSHostname,
			InsecureSkipVerify: resolverOpts.InsecureSkipVerify,
		}
	}

	client.Net = net

	u, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(server, u.Host+":") {
		server = server + ":53"
	}

	srv := strings.Replace(server, "udp://", "", -1)
	srv = strings.Replace(srv, "tcp://", "", -1)

	return &ClassicResolver{
		client: client,
		server: srv,
		opts:   resolverOpts,
	}, nil
}

// Lookup takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (r *ClassicResolver) Lookup(question dns.Question) (statute.Response, error) {
	var (
		rsp      statute.Response
		messages = PrepareMessages(question, r.opts.Ndots, r.opts.SearchList)
	)
	for _, msg := range messages {

		r.opts.Logger.Debug("attempting to resolve %s, ns: %s, ndots: %d",
			msg.Question[0].Name,
			r.server,
			r.opts.Ndots,
		)

		// Since the library doesn't include tcp.Dial time,
		// it's better to not rely on `rtt` provided here and calculate it ourselves.
		now := time.Now()
		in, _, err := r.client.Exchange(&msg, r.server)
		if err != nil {
			return rsp, err
		}

		// In case the response size exceeds 512 bytes (can happen with a lot of TXT records),
		// fallback to TCP as with UDP the response is truncated. Fallback mechanism is in-line with `dig`.
		if in.Truncated {
			switch r.client.Net {
			case "udp":
				r.client.Net = "tcp"
			case "udp4":
				r.client.Net = "tcp4"
			case "udp6":
				r.client.Net = "tcp6"
			default:
				r.client.Net = "tcp"
			}
			r.opts.Logger.Debug("response truncated; retrying now, protocol: %s",
				r.client.Net,
			)
			return r.Lookup(question)
		}

		// Pack questions in output.
		for _, q := range msg.Question {
			ques := statute.Question{
				Name:  q.Name,
				Class: dns.ClassToString[q.Qclass],
				Type:  dns.TypeToString[q.Qtype],
			}
			rsp.Questions = append(rsp.Questions, ques)
		}
		rtt := time.Since(now)

		// Get the authorities and answers.
		output := ParseMessage(in, rtt, r.server)
		rsp.Authorities = output.Authorities
		rsp.Answers = output.Answers

		if len(output.Answers) > 0 {
			// Stop iterating the searchlist.
			break
		}
	}
	return rsp, nil
}
