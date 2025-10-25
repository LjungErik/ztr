package filter

import "github.com/google/gopacket"

type NetworkFilter interface {
	GetBPF() string
	GetType() string
	RegisterPacket(packet gopacket.Packet)
}
