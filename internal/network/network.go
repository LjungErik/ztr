package network

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network/filter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Struct for handling the underlying network packet parsing

const (
	maxOutgoing = 10
)

type Network struct {
	handle   *pcap.Handle
	filters  []filter.NetworkFilter
	outgoing chan []byte
	device   string
}

func NewNetwork(iface net.Interface) *Network {
	return &Network{
		device: iface.Name,
	}
}

func (n *Network) InitializeCapture(filters ...filter.NetworkFilter) error {
	var (
		err error
	)

	if n.handle != nil {
		return fmt.Errorf("network capture already initialized")
	}

	n.outgoing = make(chan []byte, maxOutgoing)
	n.filters = filters

	n.handle, err = pcap.OpenLive(n.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface for live capture: %w", err)
	}

	bpf := joinBPF(filters...)

	log.Debugf("[%s] Setting up BPF filter: %s", n.device, bpf)

	err = n.handle.SetBPFFilter(bpf)
	if err != nil {
		return fmt.Errorf("failed to setup network filter: %w", err)
	}

	return nil
}

func (n *Network) Start(ctx context.Context) {
	pktSource := gopacket.NewPacketSource(n.handle, n.handle.LinkType())

	for {
		select {
		case data := <-n.outgoing:
			if err := n.handle.WritePacketData(data); err != nil {
				log.Errorf("failed to send packet data: %v", err)
			}
		case packet := <-pktSource.Packets():
			for _, f := range n.filters {
				err := f.RegisterPacket(packet)
				if err != nil {
					log.Errorf("failed to register packet: %v", err)
				}
			}
		case <-ctx.Done():
			log.Debugf("shutting down package capture")
			return
		}
	}
}

func (n *Network) Close() {
	if n.handle != nil {
		n.handle.Close()
	}

	n.handle = nil
}

func (n *Network) Send(data []byte) {
	n.outgoing <- data
}

func joinBPF(filters ...filter.NetworkFilter) string {
	var bpf []string
	for _, f := range filters {
		bpf = append(bpf, f.GetBPF())
	}

	return strings.Join(bpf, " or ")
}
