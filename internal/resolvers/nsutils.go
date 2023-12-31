package resolvers

import (
	"fmt"
	"github.com/bepass-org/dnsutils/internal/statute"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PrepareMessages takes a  DNS Question and returns the
// corresponding DNS messages for the same.
func PrepareMessages(q dns.Question, ndots int, searchList []string) []dns.Msg {
	var (
		possibleQNames = constructPossibleQuestions(q.Name, ndots, searchList)
		messages       = make([]dns.Msg, 0, len(possibleQNames))
	)

	for _, qName := range possibleQNames {
		msg := dns.Msg{}
		// generate a random id for the transaction.
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		// It's recommended to only send 1 question for 1 DNS message.
		msg.Question = []dns.Question{{
			Name:   qName,
			Qtype:  q.Qtype,
			Qclass: q.Qclass,
		}}
		messages = append(messages, msg)
	}

	return messages
}

// NameList returns all of the names that should be queried based on the
// config. It is based off of go's net/dns name building, but it does not
// check the length of the resulting names.
// NOTE: It is taken from `miekg/dns/clientconfig.go: func (c *ClientConfig) NameList`
// and slightly modified.
func constructPossibleQuestions(name string, ndots int, searchList []string) []string {
	// if this domain is already fully qualified, no append needed.
	if dns.IsFqdn(name) {
		return []string{name}
	}

	// Check to see if the name has more labels than Ndots. Do this before making
	// the domain fully qualified.
	hasNdots := dns.CountLabel(name) > ndots
	// Make the domain fully qualified.
	name = dns.Fqdn(name)

	// Make a list of names based off search.
	var names []string

	// If name has enough dots, try that first.
	if hasNdots {
		names = append(names, name)
	}
	for _, s := range searchList {
		names = append(names, dns.Fqdn(name+s))
	}
	// If we didn't have enough dots, try after suffixes.
	if !hasNdots {
		names = append(names, name)
	}
	return names
}

// ParseMessage takes a `dns.Message` and returns a custom
// Response data struct.
func ParseMessage(msg *dns.Msg, rtt time.Duration, server string) statute.Response {
	var resp statute.Response
	timeTaken := fmt.Sprintf("%dms", rtt.Milliseconds())

	// Parse Authorities section.
	for _, ns := range msg.Ns {
		// check for SOA record
		soa, ok := ns.(*dns.SOA)
		if !ok {
			// Currently we only check for SOA in Authority.
			// If it's not SOA, skip this message.
			continue
		}
		mname := soa.Ns + " " + soa.Mbox +
			" " + strconv.FormatInt(int64(soa.Serial), 10) +
			" " + strconv.FormatInt(int64(soa.Refresh), 10) +
			" " + strconv.FormatInt(int64(soa.Retry), 10) +
			" " + strconv.FormatInt(int64(soa.Expire), 10) +
			" " + strconv.FormatInt(int64(soa.Minttl), 10)
		h := ns.Header()
		name := h.Name
		qclass := dns.Class(h.Class).String()
		ttl := strconv.FormatInt(int64(h.Ttl), 10) + "s"
		qtype := dns.Type(h.Rrtype).String()
		auth := statute.Authority{
			Name:       name,
			Type:       qtype,
			TTL:        ttl,
			Class:      qclass,
			MName:      mname,
			Nameserver: server,
			RTT:        timeTaken,
			Status:     dns.RcodeToString[msg.Rcode],
		}
		resp.Authorities = append(resp.Authorities, auth)
	}
	// Parse Answers section.
	for _, a := range msg.Answer {
		var (
			h = a.Header()
			// Source https://github.com/jvns/dns-lookup/blob/main/dns.go#L121.
			parts = strings.Split(a.String(), "\t")
			ans   = statute.Answer{
				Name:       h.Name,
				Type:       dns.Type(h.Rrtype).String(),
				TTL:        strconv.FormatInt(int64(h.Ttl), 10) + "s",
				Class:      dns.Class(h.Class).String(),
				Address:    parts[len(parts)-1],
				RTT:        timeTaken,
				Nameserver: server,
			}
		)

		resp.Answers = append(resp.Answers, ans)
	}
	return resp
}
