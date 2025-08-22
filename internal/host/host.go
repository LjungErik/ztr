package hosts

import "net"

type Host struct {
	IP       *net.IPAddr
	MAC      *string
	Hostname *string
}
