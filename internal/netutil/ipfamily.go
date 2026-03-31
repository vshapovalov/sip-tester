package netutil

import (
	"fmt"
	"net"
)

type IPFamily string

const (
	IPFamilyV4 IPFamily = "ipv4"
	IPFamilyV6 IPFamily = "ipv6"
)

func DetectIPFamily(ip net.IP) (IPFamily, error) {
	if ip == nil {
		return "", fmt.Errorf("IP is required")
	}
	if ip.To4() != nil {
		return IPFamilyV4, nil
	}
	if ip.To16() != nil {
		return IPFamilyV6, nil
	}
	return "", fmt.Errorf("unsupported IP family for %q", ip.String())
}

func IsIPInFamily(ip net.IP, family IPFamily) bool {
	if ip == nil {
		return false
	}
	switch family {
	case IPFamilyV4:
		return ip.To4() != nil
	case IPFamilyV6:
		return ip.To4() == nil && ip.To16() != nil
	default:
		return false
	}
}

func UDPNetworkForFamily(family IPFamily) (string, error) {
	switch family {
	case IPFamilyV4:
		return "udp4", nil
	case IPFamilyV6:
		return "udp6", nil
	default:
		return "", fmt.Errorf("unsupported IP family %q", family)
	}
}
