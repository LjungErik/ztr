package arp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ArpNetworkFilter struct {
	targets     sync.Map
	found       sync.Map
	targetsLeft atomic.Int32
	finished    chan struct{}
}

func NewNetworkFilter(targetIPs []*net.IPAddr) *ArpNetworkFilter {
	nf := &ArpNetworkFilter{
		targets:     sync.Map{},
		found:       sync.Map{},
		targetsLeft: atomic.Int32{},
	}

	for _, ip := range targetIPs {
		nf.targets.Store(ip.String(), true)
	}

	nf.targetsLeft.Store(int32(len(targetIPs)))

	return nf
}

func (f *ArpNetworkFilter) GetBPF() string {
	return "arp"
}

func (f *ArpNetworkFilter) RegisterPacket(packet gopacket.Packet) error {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		go f.handleArp(arp)
	}

	return nil
}

func (f *ArpNetworkFilter) handleArp(arp *layers.ARP) {
	sourceHw := net.HardwareAddr(arp.SourceHwAddress)
	sourceIP := net.IP(arp.SourceProtAddress)

	log.Debugf("Received ARP packet: %s is asking about %s", net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.DstProtAddress))
	if _, ok := f.targets.LoadAndDelete(sourceIP.String()); ok {
		f.found.Store(sourceIP.String(), sourceHw)
		n := f.targetsLeft.Add(-1)
		log.Debugf("Targets left: %d", n)

		if n == 0 {
			close(f.finished)
		}
	}
}

func (f *ArpNetworkFilter) Wait(ctx context.Context) {
	select {
	case <-f.finished:
		log.Debugf("All targets found")
	case <-ctx.Done():
		log.Debugf("Unabled to find all targets: %v", ctx.Err())
	}
}
