package arp

import (
	"net"

	"github.com/LjungErik/ztr/internal/model/results"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPNetworkFilter struct {
	results map[string]*results.ARPResult
}

type ARPHandler interface {
	Handle(resp *layers.ARP)
}

func NewNetworkFilter(handler ARPHandler) *ARPNetworkFilter {
	return &ARPNetworkFilter{
		results: make(map[string]*results.ARPResult),
	}
}

func (f *ARPNetworkFilter) GetBPF() string {
	return "arp"
}

func (f *ARPNetworkFilter) GetType() string {
	return "arp"
}

func (f *ARPNetworkFilter) RegisterPacket(packet gopacket.Packet) {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		f.results[string(arp.SourceProtAddress)] = &results.ARPResult{
			TargetIP:     arp.SourceProtAddress,
			TargetHwAddr: arp.SourceHwAddress,
		}
	}
}

func (f *ARPNetworkFilter) NextResultForMatch(targetIP net.IP) *results.ARPResult {
	return f.results[string(targetIP)]
}
