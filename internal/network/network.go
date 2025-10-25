package network

import (
	"fmt"
	"strings"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network/filter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Struct for handling the underlying network packet parsing

const (
	pcapTimeout = time.Millisecond * 10
)

var _ Network = (*network)(nil)

type Network interface {
	RegisterFilter(f filter.NetworkFilter)
	StartCapture()
	Close()
	ProcessNextPacket()
	Send(data []byte) error
	NetworkInterface() *NetworkInterface
	GetFilter(filterType string) (filter.NetworkFilter, bool)
}

type network struct {
	handle  *pcap.Handle
	filters map[string]filter.NetworkFilter
	iface   *NetworkInterface
}

func NewNetwork(iface *NetworkInterface) *network {
	return &network{
		iface:   iface,
		filters: make(map[string]filter.NetworkFilter),
		handle:  nil,
	}
}

func (n *network) RegisterFilter(f filter.NetworkFilter) {
	n.filters[f.GetType()] = f
}

func (n *network) StartCapture() {
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

	bpf := joinBPF(n.filters)

	log.Debugf("[%s] Setting up BPF filter: %s", n.iface.Name, bpf)

	err = n.handle.SetBPFFilter(bpf)
	if err != nil {
		log.Errorf("failed to setup network filter: %v", err)

		return
	}
}

func (n *network) ProcessNextPacket() {
	raw, ci, err := n.handle.ReadPacketData()
	if err != nil {
		log.Errorf("failed to read packet data: %v", err)
	}

	packet := gopacket.NewPacket(raw, n.handle.LinkType(), gopacket.Default)
	m := packet.Metadata()
	m.CaptureInfo = ci
	m.Truncated = m.Truncated || ci.CaptureLength < ci.Length

	for _, f := range n.filters {
		f.RegisterPacket(packet)
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

func (n *network) Send(data []byte) error {
	if n.handle == nil {
		return fmt.Errorf("network capture not started")
	}

	err := n.handle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("failed to send packet data: %w", err)
	}

	return nil
}

func (n *network) NetworkInterface() *NetworkInterface {
	return n.iface
}

func (n *network) GetFilter(filterType string) (filter.NetworkFilter, bool) {
	f, ok := n.filters[filterType]
	return f, ok
}

func joinBPF(filters map[string]filter.NetworkFilter) string {
	var bpf []string
	for _, f := range filters {
		bpf = append(bpf, f.GetBPF())
	}

	return strings.Join(bpf, " or ")
}
