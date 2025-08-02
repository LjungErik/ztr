package target

import (
	"fmt"
	"net"
	"strings"
)

func Parse(target string) []*net.IPAddr {
	t := extractRange(target)

	ret := make([]*net.IPAddr, 0, len(t))
	for _, addr := range t {
		ip, err := net.ResolveIPAddr("ip", addr)
		if err != nil {
			fmt.Printf("Invalid target %s: %v\n", addr, err)

			continue
		}

		ret = append(ret, ip)
	}

	return ret
}

func extractRange(target string) []string {
	if strings.Contains(target, ";") {
		return strings.Split(target, ";")
	} else if strings.Contains(target, "/") {
		return extractIPRange(target)
	} else {
		return []string{target}
	}
}

func extractIPRange(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func removeEmptyTargets(targets []string) []string {
	var cleaned []string
	for _, target := range targets {
		if target != "" {
			cleaned = append(cleaned, target)
		}
	}
	return cleaned
}
