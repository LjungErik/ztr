package arp

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	arp_filter "github.com/LjungErik/ztr/internal/network/filter/arp"
	arp_request "github.com/LjungErik/ztr/internal/network/request/arp"
	"github.com/google/gopacket/layers"
)

var (
	ErrContextCancelled = errors.New("context cancelled")
)

type ARPScanner struct {
	network      network.Network
	reciever     chan *layers.ARP
	targets      []*net.IPAddr
	targetsMap   map[string]*network.Host
	sourceIPv4   net.IP
	sourceHwAddr net.HardwareAddr
}

type ScanResults struct {
	Found bool
	*network.Host
}

type ARPScanResults struct {
	Found    []network.Host
	NotFound []*net.IPAddr
}

func NewARPScanner(net network.Network, targets []*net.IPAddr) *ARPScanner {
	s := &ARPScanner{
		network:    net,
		reciever:   make(chan *layers.ARP),
		targets:    targets,
		targetsMap: make(map[string]*network.Host, len(targets)),
	}

	for _, ip := range targets {
		s.targetsMap[ip.String()] = nil
	}

	s.network.RegisterFilter(
		arp_filter.NewNetworkFilter(s))

	return s
}

func (s *ARPScanner) Run(ctx context.Context) (*ARPScanResults, error) {
	// Select for handling recieved messages
	// Have a timeout for sending arp requests at a set interval
	// Have a batch of arp requests to send
	// Remove
	for {
		select {
		case resp := <-s.reciever:
			s.process(resp)
		case <-ctx.Done():
			log.Debugf("Context cancelled ending processing")

			return s.results(), ErrContextCancelled
		}
	}

	return s.results(), nil
}

func (s *ARPScanner) Handle(resp *layers.ARP) {
	s.reciever <- resp
}

func (s *ARPScanner) process(resp *layers.ARP) {
	// Processes ARP request and register if ARP is related to the given target.
	// Update internal map with true of false to determine if retry should be done for the given target or not
	sourceIP := net.IP(resp.SourceProtAddress)
	sourceHwAddr := net.HardwareAddr(resp.SourceHwAddress)

	v, ok := s.targetsMap[sourceIP.String()]
	if ok && v == nil {
		s.targetsMap[sourceIP.String()] = &network.Host{
			IP:        &sourceIP,
			HwAddress: &sourceHwAddr,
		}
	}
}

func (s *ARPScanner) results() *ARPScanResults {
	return nil
}

type BatchRequest struct {
	targetsIPv4 []net.IP
}

func (s *ARPScanner) sendBatch(br BatchRequest) error {
	// Sends a batch arp request
	for _, targetIPv4 := range br.targetsIPv4 {
		arp := arp_request.NewARPRequest(s.sourceIPv4, targetIPv4, s.sourceHwAddr)

		payload, err := arp.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal arp request: %w", err)
		}

		s.network.Send(payload)
	}

	return nil

}
