package arp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPNetworkFilter struct {
	handler ARPHandler
}

type ARPHandler interface {
	Handle(resp *layers.ARP)
}

func NewNetworkFilter(handler ARPHandler) *ARPNetworkFilter {
	return &ARPNetworkFilter{
		handler: handler,
	}
}

func (f *ARPNetworkFilter) GetBPF() string {
	return "arp"
}

func (f *ARPNetworkFilter) RegisterPacket(packet gopacket.Packet) error {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		f.handler.Handle(arp)
	}

	return nil
}
