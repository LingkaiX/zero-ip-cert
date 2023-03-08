package ipcert

import (
	"bytes"
	"net"
)

// ipv4 only, according to:
// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
func isReversed(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsUnspecified() ||
		isIPInSubnet(ip, net.ParseIP("100.64.0.0"), net.CIDRMask(10, 32)) ||
		isIPInSubnet(ip, net.ParseIP("127.0.0.0"), net.CIDRMask(8, 32)) ||
		isIPInSubnet(ip, net.ParseIP("169.254.0.0"), net.CIDRMask(16, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.0"), net.CIDRMask(29, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.8"), net.CIDRMask(32, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.9"), net.CIDRMask(32, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.10"), net.CIDRMask(32, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.170"), net.CIDRMask(32, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.0.171"), net.CIDRMask(32, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.0.2.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.31.196.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.52.193.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.88.99.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("192.175.48.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("198.18.0.0"), net.CIDRMask(15, 32)) ||
		isIPInSubnet(ip, net.ParseIP("198.51.100.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("203.0.113.0"), net.CIDRMask(24, 32)) ||
		isIPInSubnet(ip, net.ParseIP("240.0.0.0"), net.CIDRMask(4, 32)) ||
		isIPInSubnet(ip, net.ParseIP("255.255.255.255"), net.CIDRMask(32, 32))

}

// only valid for IPv4, return false otherwise
func isIPInSubnet(ip net.IP, subnet net.IP, mask net.IPMask) bool {
	if len(mask) != net.IPv4len {
		return false
	}
	ip = ip.To4()
	subnet = subnet.To4()
	if ip == nil || subnet == nil {
		return false
	}
	if bytes.Equal(mask, []byte{255, 255, 255, 255}) && ip.Equal(subnet) {
		return true
	}

	mIP := make([]byte, net.IPv4len)
	mSubnet := make([]byte, net.IPv4len)
	for i := 0; i < 4; i++ {
		mIP[i] = ip[i] & mask[i]
		mSubnet[i] = subnet[i] & mask[i]
	}
	return bytes.Equal(mIP, mSubnet)
}
