package util

import (
	"net"
	"strings"
)

var privateCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		privateCIDRs = append(privateCIDRs, n)
	}
}

// IsInternalHost returns true if the host is considered internal or loopback.
func IsInternalHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".internal") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range privateCIDRs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}
