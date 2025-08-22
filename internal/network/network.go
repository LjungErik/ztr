package network

import (
	"context"
	"fmt"
	"net"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Struct for handling the underlying network packet parsing

const (
	maxOutgoing = 10
)

type Network struct {
	handle   *pcap.Handle
	filter   NetworkFilter
	outgoing chan []byte
}

type NetworkFilter interface {
	GetBPF() string
	CheckPacket(packet gopacket.Packet) error
}

func Initialize(iface net.Interface, filter NetworkFilter) (*Network, error) {
	var (
		err error
		n   *Network = &Network{}
	)

	n.outgoing = make(chan []byte, maxOutgoing)

	n.handle, err = pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface for live capture: %w", err)
	}

	err = n.handle.SetBPFFilter(filter.GetBPF())
	if err != nil {
		return nil, fmt.Errorf("failed to setup network filter")
	}

	return n, nil
}

func (n *Network) StartCapture(ctx context.Context) {
	pktSource := gopacket.NewPacketSource(n.handle, n.handle.LinkType())

	for {
		select {
		case data := <-n.outgoing:
			if err := n.handle.WritePacketData(data); err != nil {
				log.Errorf("failed to send packet data: %v", err)
			}
		case packet := <-pktSource.Packets():
			err := n.filter.CheckPacket(packet)
			if err != nil {
				log.Errorf("failed to check package: %v", err)
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
