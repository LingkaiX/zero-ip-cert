package ipcert

import (
	"net"
	"testing"
)

var p = net.ParseIP

var m = net.CIDRMask

func TestIsIPInSubnet(t *testing.T) {
	if isIPInSubnet(p("255.255.255.255"), p("255.255.255.255"), m(32, 32)) != true ||
		isIPInSubnet(p("0.0.0.0"), p("0.0.0.0"), m(8, 32)) != true ||
		isIPInSubnet(p("192.168.10.111"), p("192.168.10.0"), m(24, 32)) != true ||
		isIPInSubnet(p("111.111.111.111"), p("111.111.255.255"), m(16, 32)) != true ||
		isIPInSubnet(p("10.10.10.10"), p("10.11.0.123"), m(8, 32)) != true ||
		isIPInSubnet(p("111.241.128.44"), p("111.255.0.0"), m(12, 32)) != true ||
		isIPInSubnet(p("111.241.128.44"), p("111.255.0.0"), m(13, 32)) != false {
		t.Fatalf("Test failded within function: isIPInSubnet")
	}
}

func TestIsReversed(t *testing.T) {
	if isReversed(p("255.255.255.255")) != true ||
		isReversed(p("0.0.0.0")) != true ||
		isReversed(p("10.10.11.22")) != true ||
		isReversed(p("127.123.12.1")) != true ||
		isReversed(p("192.0.0.8")) != true ||
		isReversed(p("192.0.0.123")) != true ||
		isReversed(p("192.0.2.22")) != true ||
		isReversed(p("192.52.193.0")) != true ||
		isReversed(p("198.19.255.255")) != true ||
		isReversed(p("111.241.128.44")) != false {
		t.Fatalf("Test failded within function: isReversed")
	}
}
