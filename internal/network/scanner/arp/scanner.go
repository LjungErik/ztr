package arp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	arp_filter "github.com/LjungErik/ztr/internal/network/filter/arp"
	arp_request "github.com/LjungErik/ztr/internal/network/request/arp"
	"github.com/google/gopacket/layers"
)

const (
	defaultMaxRetries = 50

	defaultSendInterval = time.Millisecond * 200
)

var (
	ErrContextCancelled = errors.New("context cancelled")
)

type ARPScanner struct {
	network            network.Network
	reciever           chan *layers.ARP
	targetsIPv4        []net.IP
	targetsRetriesLeft map[string]int
	targetsMap         map[string]*network.Host
	sourceIPv4         net.IP
	sourceHwAddr       net.HardwareAddr
}

type ScanResults struct {
	Found bool
	*network.Host
}

type ARPScanResults struct {
	Found    []network.Host
	NotFound []*net.IP
}

func NewARPScanner(net network.Network, iface *network.NetworkInterface, targets []net.IP) (*ARPScanner, error) {
	s := &ARPScanner{
		network:            net,
		reciever:           make(chan *layers.ARP),
		targetsIPv4:        targets,
		targetsMap:         make(map[string]*network.Host, len(targets)),
		targetsRetriesLeft: make(map[string]int, len(targets)),
	}

	s.network.RegisterFilter(
		arp_filter.NewNetworkFilter(s))

	for _, target := range targets {
		s.targetsMap[target.String()] = nil
		s.targetsRetriesLeft[target.String()] = defaultMaxRetries
	}

	ip, err := iface.GetIPv4()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IPv4 address: %v", err)
	}

	s.sourceIPv4 = ip
	s.sourceHwAddr = iface.GetHwAddress()

	return s, nil
}

func (s *ARPScanner) Run(ctx context.Context) ([]network.Host, error) {
	var ticker = time.NewTicker(defaultSendInterval)

	more := s.sendARPRequests()
	if !more {
		log.Debugf("No targets to send ARP requests for")

		return s.results(), nil
	}

	for {
		select {
		case resp := <-s.reciever:
			s.process(resp)
		case <-ctx.Done():
			log.Debugf("Context cancelled ending processing")

			return s.results(), ErrContextCancelled
		case <-ticker.C:
			more := s.sendARPRequests()

			if !more {
				log.Debugf("No more targets to send ARP requests for")

				return s.results(), nil
			}
		}
	}
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

func (s *ARPScanner) results() []network.Host {
	var found []network.Host
	for _, host := range s.targetsMap {
		if host != nil {
			found = append(found, *host)
		}
	}

	return found
}

func (s *ARPScanner) sendARPRequests() bool {
	// Get next batch of targets to send ARP request for
	sentRequests := false

	for _, target := range s.targetsIPv4 {
		if v, ok := s.targetsMap[target.String()]; ok && v != nil {
			continue
		}

		if retriesLeft := s.targetsRetriesLeft[target.String()]; retriesLeft <= 0 {
			log.Debugf("No more retries left for target %s", target.String())

			continue
		}

		arp := arp_request.NewARPRequest(s.sourceIPv4, target, s.sourceHwAddr)

		payload, err := arp.Marshal()
		if err != nil {
			log.Errorf("failed to marshal ARP request: %v", err)
			continue
		}

		s.network.Send(payload)
		sentRequests = true

		s.targetsRetriesLeft[target.String()] -= 1
	}

	return sentRequests
}
