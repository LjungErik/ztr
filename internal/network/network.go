package network

import (
	"fmt"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	pcapTimeout time.Duration = 10 * time.Microsecond
)

type Network interface {
	StartCapture(bpf string) (*gopacket.PacketSource, error)
	SendPacket(data []byte) error
	NetworkInterface() *NetworkInterface
	Close()
}

type network struct {
	handle *pcap.Handle
	iface  *NetworkInterface
}

func NewNetwork(iface *NetworkInterface) Network {
	return &network{
		iface:  iface,
		handle: nil,
	}
}

func (n *network) StartCapture(bpf string) (*gopacket.PacketSource, error) {
	var (
		err error
	)

	if n.handle != nil {
		return nil, fmt.Errorf("failed to start capture: network capture already started")
	}

	n.handle, err = pcap.OpenLive(n.iface.Name, 1600, true, pcapTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface for live capture: %w", err)
	}

	log.Debugf("[%s] Setting up BPF filter: %s", n.iface.Name, bpf)

	err = n.handle.SetBPFFilter(bpf)
	if err != nil {
		return nil, fmt.Errorf("failed to setup network filter: %w", err)
	}

	src := gopacket.NewPacketSource(n.handle, n.handle.LinkType())

	return src, nil
}

func (n *network) ReadNextPacket() (gopacket.Packet, error) {
	raw, ci, err := n.handle.ReadPacketData()
	if err != nil {
		log.Errorf("failed to read packet data: %v", err)
	}

	packet := gopacket.NewPacket(raw, n.handle.LinkType(), gopacket.Default)
	m := packet.Metadata()
	m.CaptureInfo = ci
	m.Truncated = m.Truncated || ci.CaptureLength < ci.Length

	return packet, nil
}

func (n *network) SendPacket(data []byte) error {
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

func (n *network) Close() {
	log.Debugf("closing network capture")
	if n.handle != nil {
		n.handle.Close()
		log.Debugf("network capture closed")
	}

	n.handle = nil
}
