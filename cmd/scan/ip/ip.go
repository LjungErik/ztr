package ip

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	"github.com/LjungErik/ztr/internal/network/filter/arp"
	arp_req "github.com/LjungErik/ztr/internal/network/request/arp"
	"github.com/LjungErik/ztr/internal/target"
	"github.com/spf13/cobra"
)

const (
	defaultTimeout = 30 * time.Second
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
	targets := target.Parse(args[0])
	if len(targets) == 0 {
		return fmt.Errorf("no valid targets provided")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	if len(ifaces) == 0 {
		return fmt.Errorf("no network interfaces found")
	}

	iface := ifaces[0]
	fmt.Printf("Using interface %s\n", iface.Name)

	foundHosts, err := performARPScan(iface, targets)
	if err != nil {
		return fmt.Errorf("failed to perform ARP scan: %w", err)
	}

	fmt.Println(" --- Found Hosts --- ")

	for _, host := range foundHosts {
		fmt.Printf(" - %s\n", host)
	}

	return nil
}

func performARPScan(iface net.Interface, targets []*net.IPAddr) ([]network.Host, error) {
	nw := network.NewNetwork(iface)
	defer nw.Close()

	arpFilter := arp.NewNetworkFilter(targets)
	err := nw.InitializeCapture(arpFilter)
	if err != nil {
		log.Errorf("failed to initialize network capture: %v", err)
		return nil, fmt.Errorf("failed to initialize network capture: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)

	go nw.Start(ctx)

	for _, target := range targets {
		arpReq := arp_req.NewARPRequest(nil, target, iface.HardwareAddr)

		data, err := arpReq.Marshal()
		if err != nil {
			log.Errorf("failed to marshal ARP request: %v", err)
			continue
		}

		nw.Send(data)
	}

	// Wait for results or timeout of context
	arpFilter.Wait(ctx)

	cancel()

	return arpFilter.Results(), nil
}
