package ip

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	broadcastHwAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	emptyHwAddr     = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

type ARPRequest struct {
	TargetIP  net.IP
	SrcIP     net.IP
	SrcHwAddr net.HardwareAddr
}

func NewARPRequest(srcIP, target net.IP, srcHwAddr net.HardwareAddr) *ARPRequest {
	return &ARPRequest{
		TargetIP:  target,
		SrcIP:     srcIP,
		SrcHwAddr: srcHwAddr,
	}
}

func (r *ARPRequest) Marshal() ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       r.SrcHwAddr,
		DstMAC:       broadcastHwAddr,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(r.SrcHwAddr),
		SourceProtAddress: []byte(r.SrcIP),
		DstHwAddress:      []byte(emptyHwAddr),
		DstProtAddress:    []byte(r.TargetIP),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
