package ip

import (
	"context"
	"net"

	"github.com/LjungErik/ztr/internal/network"
)

type IPScanner struct {
	network network.Network
}

type IPScanResults struct {
	Found []network.Host
}

type Option func(*IPScanner)

func NewIPScanner(net network.Network, targets []net.IP, options ...Option) *IPScanner {
	scanner := &IPScanner{
		network: net,
	}

	for _, opt := range options {
		opt(scanner)
	}

	return scanner
}

func (s *IPScanner) Scan(ctx context.Context) (*IPScanResults, error) {
	results := &IPScanResults{}

	for s.hasMoreToScan() {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			s.process()
		}
	}

	return results, nil
}

func (s *IPScanner) process() {

	// Process next incoming packet
	s.network.ProcessNextPacket()

	// define targets as a tree structure of arithmetic formula
	// e.g. (arp + dns) or (icmp + dns)

}

func (s *IPScanner) hasMoreToScan() bool {
	// Determine if there are more IPs to scan
	return false
}
