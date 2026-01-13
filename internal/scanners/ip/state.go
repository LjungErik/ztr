package ip

import (
	"net"
	"time"
)

const (
	maxRetries    = 15
	retryInterval = 10 * time.Second
)

type ScanType int

const (
	ARPScan ScanType = 1
	TCPScan ScanType = 2
)

type TargetState struct {
	Confirmed bool
	LastSent  time.Time
	IP        net.IP
	Retries   int
}
