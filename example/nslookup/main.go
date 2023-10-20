package main

import (
	"context"
	"fmt"
	"github.com/bepass-org/dnsutils"
	"net"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
)

var serverAddress string

var resolver *dnsutils.Resolver

func main() {
	resolver = dnsutils.NewResolver(
		dnsutils.WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			fmt.Println("Dialing", addr)
			return net.Dial(network, addr)
		}),
	)
	err := resolver.SetDNSServer("https://1.1.1.1/dns-query")
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
	if len(tokens) < 1 {
		fmt.Println("Invalid input.")
		return
	}

	switch tokens[0] {
	case "server":
		if len(tokens) < 2 {
			fmt.Println("Invalid input.")
			return
		}
		serverAddress = tokens[1]
		err := resolver.SetDNSServer(serverAddress)
		if err != nil {
			fmt.Println("Error setting DNS server:", err)
			return
		}
		fmt.Println("Server set to:", serverAddress)
	case "exit":
		os.Exit(0)
	case "domain":
		if len(tokens) < 2 {
			fmt.Println("Invalid input.")
			return
		}
		printIPs(tokens[1])
	default:
		printIPs(tokens[0])
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "server", Description: "Set the DNS server address"},
		{Text: "domain", Description: "Resolve domain for ip addresses"},
		{Text: "exit", Description: "Exit the program"},
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
