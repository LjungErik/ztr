package filter

import "github.com/google/gopacket"

type NetworkFilter interface {
	GetBPF() string
	RegisterPacket(packet gopacket.Packet) error
}
