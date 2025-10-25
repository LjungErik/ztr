package results

import "net"

type ARPResult struct {
	TargetIP     net.IP
	TargetHwAddr net.HardwareAddr
}
