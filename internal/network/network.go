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
}

func Initialize(iface net.Interface, filters ...filter.NetworkFilter) (*Network, error) {
	var (
		err error
		n   *Network = &Network{}
	)

	n.outgoing = make(chan []byte, maxOutgoing)

	n.handle, err = pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface for live capture: %w", err)
	}

	bpf := joinBPF(filters...)

	log.Debugf("[%s] Setting up BPF filter: %s", iface.Name, bpf)

	err = n.handle.SetBPFFilter(bpf)
	if err != nil {
		return nil, fmt.Errorf("failed to setup network filter: %w", err)
	}

	return n, nil
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
	n.handle.Close()
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
