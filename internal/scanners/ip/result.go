package ip

import "net"

type TargetResult struct {
	IP             net.IP
	HwAddr         net.HardwareAddr
	CompletedScans ScanType
}
