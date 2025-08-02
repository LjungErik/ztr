package target

import (
	"net"
	"strings"
)

func Parse(target string) []string {
	var ret []string

	if strings.Contains(target, ";") {
		ret = strings.Split(target, ";")
	} else if strings.Contains(target, "/") {
		ret = extractIPRange(target)
	} else {
		ret = []string{target}
	}

	return removeEmptyTargets(ret)
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
