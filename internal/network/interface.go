package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/LjungErik/ztr/internal/log"
)

var (
	ErrIPv4NotFound = errors.New("ipv4 address not found for interface")
)

type NetworkInterface struct {
	net.Interface
}

func NewNetworkInterface(iface net.Interface) *NetworkInterface {
	return &NetworkInterface{iface}
}

func (n *NetworkInterface) GetIPv4() (net.IP, error) {
	addrs, err := n.Addrs()
	if err != nil {
		log.Errorf("failed to get interface addresses: %v", err)
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		log.Debugf("Interface %s has address %s", n.Name, addr.String())

		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			return ipNet.IP.To4(), nil
		}
	}

	return nil, ErrIPv4NotFound
}

func (n *NetworkInterface) GetHwAddress() net.HardwareAddr {
	return n.HardwareAddr
}
