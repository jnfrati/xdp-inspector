package xdp_test

import (
	"net/netip"
	"testing"

	"github.com/jnfrati/xdp-inspector/types"
)

func TestIpv4Parsing(t *testing.T) {
	event := &types.EventPayload{}
	data := []byte{
		2,                // Source IP Protocol ipv4
		192, 168, 0, 185, // Source IP
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding?
		2,                 // Dest IP protocol ipv4
		192, 168, 88, 253, // Dest IP
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding?
		162, 169, // Source port
		162, 169, // Dest port
		17,           // Protocol
		0, 220, 0, 0, // Packet len
		42, 40, 187, 31, 118, 7, 0, 0, // Timestamp
	}

	err := event.FromBytes(data)
	if err != nil {
		t.Errorf("Failed to parse event: %v", err)
	}

	srcIp := netip.AddrFrom4([4]byte{192, 168, 0, 185})

	// How do I add assertions?
	if event.SourceIP.Compare(srcIp) == 0 {
		t.Logf("Source IP parsed correctly: %v", event.SourceIP)
	} else {
		t.Errorf("Source IP parsed incorrectly: got %v, want %v", event.SourceIP, srcIp)
	}

	dstIp := netip.AddrFrom4([4]byte{192, 168, 88, 253})

	if event.DestinationIP.Compare(dstIp) == 0 {
		t.Logf("Destination IP parsed correctly: %v", event.DestinationIP)
	} else {
		t.Errorf("Destination IP parsed incorrectly: got %v, want %v", event.DestinationIP, dstIp)
	}

	// Add assertions to verify the parsed values
}

func TestIpv6Parsing(t *testing.T) {
	event := &types.EventPayload{}
	data := []byte{
		10, // Source IP Protocol ipv6
		// Source IP (IPv6)
		32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		// Padding?
		10, // Dest IP protocol ipv6
		// Dest IP (IPv6)
		32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		// Padding?
		162, 169, // Source port
		162, 169, // Dest port
		17,           // Protocol
		0, 220, 0, 0, // Packet len
		42, 40, 187, 31, 118, 7, 0, 0, // Timestamp
	}

	err := event.FromBytes(data)
	if err != nil {
		t.Errorf("Failed to parse event: %v", err)
	}

	srcIpv6 := netip.AddrFrom16([16]byte(data[1:17]))

	if event.SourceIP.Compare(srcIpv6) == 0 {
		t.Logf("Source IP parsed correctly: %v", event.SourceIP)
	} else {
		t.Errorf("Source IP parsed incorrectly: got %v, want %v", event.SourceIP, srcIpv6)
	}

	dstIpv6 := netip.AddrFrom16([16]byte(data[18:34]))
	if event.DestinationIP.Compare(dstIpv6) == 0 {
		t.Logf("Destination IP parsed correctly: %v", event.DestinationIP)
	} else {
		t.Errorf("Destination IP parsed incorrectly: got %v, want %v", event.DestinationIP, dstIpv6)
	}

	// Add assertions to verify the parsed values
}
