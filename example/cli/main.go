package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/c-bata/go-prompt"
)

var serverAddress string

func main() {
	fmt.Println("Welcome to Go NSLookup!")
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
	var resolver *net.Resolver
	if serverAddress != "" {
		address := serverAddress
		if !strings.Contains(serverAddress, ":") {
			address = serverAddress + ":53"
		}
		resolver = &net.Resolver{
			PreferGo:     true,
			StrictErrors: false,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.Dial("udp", address)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(context.Background(), "ip", domain)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("IP addresses for %s:\n", domain)
	for _, ip := range ips {
		fmt.Println(ip)
	}
}
