package main

import (
	"fmt"
	"github.com/bepass-org/dnsutils"
	"strings"

	"github.com/c-bata/go-prompt"
)

var serverAddress string

var resolver *dnsutils.Resolver

func main() {
	resolver = dnsutils.NewResolver()
	err := resolver.SetDNSServer("https://8.8.8.8/dns-query")
	if err != nil {
		fmt.Println("Error setting DNS server:", err)
		return
	}
	fmt.Println("Welcome to Bepass NSLookup!")
	p := prompt.New(executor, completer, prompt.OptionPrefix("> "))
	p.Run()
}

func executor(s string) {
	tokens := strings.SplitN(s, " ", 2)
	if len(tokens) < 2 {
		fmt.Println("Invalid input.")
		return
	}

	switch tokens[0] {
	case "server":
		serverAddress = tokens[1]
		err := resolver.SetDNSServer(serverAddress)
		if err != nil {
			fmt.Println("Error setting DNS server:", err)
			return
		}
		fmt.Println("Server set to:", serverAddress)
	case "domain":
		printIPs(tokens[1])
	default:
		fmt.Println("Unknown command. Use 'server' or 'domain'.")
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "server", Description: "Set the DNS server address"},
		{Text: "domain", Description: "Resolve domain for ip addresses"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func printIPs(domain string) {
	ips, err := resolver.LookupIP(domain)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("IP addresses for %s:\n", domain)
	for _, ip := range ips {
		fmt.Println(ip)
	}
}
