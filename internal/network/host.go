package network

import (
	"fmt"
	"net"
)

const (
	defaultValue = "unknown"
)

type Host struct {
	IP        *net.IP
	HwAddress *net.HardwareAddr
	Hostname  *string
}

func (h Host) String() string {
	ipStr := defaultValue
	if h.IP != nil {
		ipStr = h.IP.String()
	}

	hwStr := defaultValue
	if h.HwAddress != nil {
		hwStr = h.HwAddress.String()
	}

	hostnameStr := defaultValue
	if h.Hostname != nil {
		hostnameStr = *h.Hostname
	}

	return fmt.Sprintf("IP: %s, MAC: %s, Hostname: %s", ipStr, hwStr, hostnameStr)
}
