package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"masterdnsvpn-go/mobile"
)

// connectMasterdns starts the MasterDNS DNS tunnel and blocks until Ctrl+C or failure.
// MasterDNS exposes its own SOCKS5 proxy directly on profile.Host:profile.Port.
func connectMasterdns(profile *Profile) {
	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       MasterDNS\n")
	if !profile.IsLocked {
		fmt.Printf("  Domain:     %s\n", profile.Domain)
	} else {
		fmt.Println("  Domain:     [hidden]")
	}
	fmt.Printf("  SOCKS5:     %s\n", listenAddr)
	fmt.Println()

	if profile.MasterdnsKey == "" {
		fmt.Fprintln(os.Stderr, "  Error: MasterDNS encryption key is required.\n"+
			"  Make sure the profile was exported from the SlipNet app with a MasterDNS key set.")
		return
	}
	if profile.Domain == "" {
		fmt.Fprintln(os.Stderr, "  Error: Profile is missing tunnel domain")
		return
	}

	// Build newline-separated resolver IPs from the profile's resolver list.
	// MasterDNS wants plain IP addresses (no port, no auth flag).
	resolverIPs := buildMasterdnsResolvers(profile.Resolvers)
	if resolverIPs == "" {
		fmt.Fprintln(os.Stderr, "  Error: No resolver IPs found in profile")
		return
	}

	fmt.Println("  Connecting...")

	newClient := func() (*mobile.Client, error) {
		return mobile.NewClient(
			profile.Domain,
			profile.MasterdnsKey,
			profile.MasterdnsEncMethod,
			resolverIPs,
			profile.Port,
			profile.Host,
		)
	}

	client, err := newClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: Failed to create MasterDNS client: %v\n", err)
		return
	}

	if err := client.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "  Error: Failed to start MasterDNS tunnel: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy listening on %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Configure your apps to use:")
	fmt.Printf("    SOCKS5 proxy: %s\n", listenAddr)
	fmt.Println()
	fmt.Printf("  Or: curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	reconnectDelay := 3 * time.Second
	for {
		select {
		case <-sigCh:
			fmt.Println()
			fmt.Println("  Disconnecting...")
			done := make(chan struct{})
			go func() { client.Stop(); close(done) }()
			select {
			case <-done:
				fmt.Println("  Done.")
			case <-time.After(5 * time.Second):
				fmt.Println("  Shutdown timed out, forcing exit.")
			}
			return
		case <-time.After(5 * time.Second):
			if !client.IsRunning() {
				fmt.Printf("\n  Tunnel died, reconnecting in %v...\n", reconnectDelay)
				client.Stop()
				time.Sleep(reconnectDelay)

				client, err = newClient()
				if err != nil {
					fmt.Printf("  Failed to create client: %v\n", err)
					continue
				}
				if err := client.Start(); err != nil {
					fmt.Printf("  Reconnect failed: %v\n", err)
					continue
				}
				fmt.Println("  Reconnected!")
			}
		}
	}
}

// buildMasterdnsResolvers converts the profile's comma-separated resolver list
// (host:port:auth format) into a newline-separated list of host IPs for MasterDNS.
// MasterDNS only needs the IP/hostname, not the port or auth flag.
func buildMasterdnsResolvers(resolversStr string) string {
	if resolversStr == "" {
		return ""
	}
	var ips []string
	for _, r := range strings.Split(resolversStr, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		// Format is host:port:auth — extract just the host part.
		parts := strings.SplitN(r, ":", 2)
		host := parts[0]
		if host != "" {
			ips = append(ips, host)
		}
	}
	return strings.Join(ips, "\n")
}
