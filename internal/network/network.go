package network

import (
	"context"
	"strings"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network/filter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Struct for handling the underlying network packet parsing

const (
	maxOutgoing = 10
	pcapTimeout = time.Millisecond * 10
)

type Network interface {
	RegisterFilter(f filter.NetworkFilter)
	StartCapture(ctx context.Context)
	Close()
	Send(data []byte)
}

type network struct {
	handle   *pcap.Handle
	filters  []filter.NetworkFilter
	outgoing chan []byte
	iface    *NetworkInterface
}

func NewNetwork(iface *NetworkInterface) *network {
	return &network{
		iface:    iface,
		outgoing: make(chan []byte, maxOutgoing),
		filters:  []filter.NetworkFilter{},
		handle:   nil,
	}
}

func (n *network) RegisterFilter(f filter.NetworkFilter) {
	n.filters = append(n.filters, f)
}

func (n *network) StartCapture(ctx context.Context) {
	var (
		err error
	)

	if n.handle != nil {
		log.Debugf("network capture already started")

		return
	}

	n.handle, err = pcap.OpenLive(n.iface.Name, 1600, true, pcapTimeout)
	if err != nil {
		log.Errorf("failed to open interface for live capture: %v", err)

		return
	}

	bpf := joinBPF(n.filters...)

	log.Debugf("[%s] Setting up BPF filter: %s", n.iface.Name, bpf)

	err = n.handle.SetBPFFilter(bpf)
	if err != nil {
		log.Errorf("failed to setup network filter: %v", err)

		return
	}

	n.start(ctx)
}

func (n *network) start(ctx context.Context) {
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

func (n *network) Close() {
	log.Debugf("closing network capture")
	if n.handle != nil {
		n.handle.Close()
		log.Debugf("network capture closed")
	}

	n.handle = nil
}

func (n *network) Send(data []byte) {
	n.outgoing <- data
}

func joinBPF(filters ...filter.NetworkFilter) string {
	var bpf []string
	for _, f := range filters {
		bpf = append(bpf, f.GetBPF())
	}

	return strings.Join(bpf, " or ")
}
