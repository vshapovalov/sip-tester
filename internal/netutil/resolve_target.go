package netutil

import (
	"fmt"
	"net"
	"strconv"
)

type ResolvedTarget struct {
	Hostname   string
	Port       uint16
	RemoteIP   net.IP
	RemoteAddr string
	Family     IPFamily
}

func ResolveSIPTarget(host string, port uint16, family IPFamily) (ResolvedTarget, error) {
	return resolveSIPTargetWithLookup(host, port, family, net.LookupIP)
}

func resolveSIPTargetWithLookup(host string, port uint16, family IPFamily, lookup func(string) ([]net.IP, error)) (ResolvedTarget, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !IsIPInFamily(ip, family) {
			return ResolvedTarget{}, fmt.Errorf("host literal IP family does not match local-ip family %s: %s", family, ip.String())
		}
		return buildResolvedTarget(host, port, ip, family), nil
	}

	ips, err := lookup(host)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("lookup host %q: %w", host, err)
	}
	for _, ip := range ips {
		if IsIPInFamily(ip, family) {
			return buildResolvedTarget(host, port, ip, family), nil
		}
	}

	if family == IPFamilyV4 {
		return ResolvedTarget{}, fmt.Errorf("local-ip is IPv4 but host %s has no IPv4 address", host)
	}
	return ResolvedTarget{}, fmt.Errorf("local-ip is IPv6 but host %s has no IPv6 address", host)
}

func buildResolvedTarget(host string, port uint16, ip net.IP, family IPFamily) ResolvedTarget {
	return ResolvedTarget{
		Hostname:   host,
		Port:       port,
		RemoteIP:   ip,
		RemoteAddr: net.JoinHostPort(ip.String(), strconv.Itoa(int(port))),
		Family:     family,
	}
}
