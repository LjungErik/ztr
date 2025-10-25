package network

import (
	"errors"
	"net"

	"github.com/LjungErik/ztr/internal/log"
)

var (
	ErrIPv4NotFound = errors.New("ipv4 address not found for interface")
)

type NetworkInterface struct {
	net.Interface
	ipv4         net.IP
	hardwareAddr net.HardwareAddr
}

func NewNetworkInterface(iface net.Interface) *NetworkInterface {
	return &NetworkInterface{
		ipv4:         getIPV4(iface),
		hardwareAddr: iface.HardwareAddr,
	}
}

func (n *NetworkInterface) GetIPv4() net.IP {
	return n.ipv4
}

func (n *NetworkInterface) GetHwAddress() net.HardwareAddr {
	return n.hardwareAddr
}

func getIPV4(iface net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Errorf("failed to get interface addresses: %v", err)
		return net.IPv4(0, 0, 0, 0)
	}

	for _, addr := range addrs {
		log.Debugf("Interface %s has address %s", iface.Name, addr.String())

		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			return ipNet.IP.To4()
		}
	}

	return net.IPv4(0, 0, 0, 0)
}
