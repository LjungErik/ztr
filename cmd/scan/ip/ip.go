package ip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/LjungErik/ztr/internal/network"
	arp_scan "github.com/LjungErik/ztr/internal/network/scanner/arp"
	"github.com/LjungErik/ztr/internal/target"
	"github.com/spf13/cobra"
)

const (
	defaultTimeout = 300 * time.Second
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip <target(s)>",
		Short: "IP command for scanning potential hosts on a network (192.168.1.1, 10.0.0.0/24, 192.168.1.1;172.16.1.1, test.example.com)",
		Args:  cobra.MinimumNArgs(1),
		RunE:  exec,
	}

	return cmd
}

func exec(cmd *cobra.Command, args []string) error {
	targets := target.ParseIPv4(args[0])
	if len(targets) == 0 {
		return fmt.Errorf("no valid targets provided")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	if len(ifaces) < 2 {
		return fmt.Errorf("no network interfaces found")
	}

	iface := ifaces[1]
	fmt.Printf("Using interface %s\n", iface.Name)

	netFace := network.NewNetworkInterface(iface)

	nw := network.NewNetwork(netFace)
	defer nw.Close()

	scanner, err := arp_scan.NewARPScanner(nw, netFace, targets)
	if err != nil {
		return fmt.Errorf("failed to create ARP scanner: %w", err)
	}

	wg := &sync.WaitGroup{}

	foundHosts, err := startScan(nw, scanner, wg)
	if err != nil {
		return fmt.Errorf("failed to start ARP scan: %w", err)
	}

	if len(foundHosts) == 0 {
		fmt.Println("No hosts found")
		return nil
	}

	fmt.Println(" --- Found Hosts --- ")
	fmt.Printf("Found %d hosts out of %d:\n", len(foundHosts), len(targets))

	for _, host := range foundHosts {
		fmt.Printf(" - %s\n", host)
	}

	wg.Wait()

	return nil
}

func startScan(nw network.Network, scanner *arp_scan.ARPScanner, wg *sync.WaitGroup) ([]network.Host, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	wg.Add(1)

	go func() {
		defer wg.Done()
		nw.StartCapture(ctx)
	}()

	results, err := scanner.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to run ARP scanner: %w", err)
	}

	return results, nil
}
