package types

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"syscall"
	"time"
)

type Protocol uint8

func (p Protocol) String() string {
	switch p {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

type EventPayload struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	Protocol        Protocol
	PacketLength    uint32
	Direction       uint8
	Timestamp       time.Time
}

func (ep *EventPayload) FromBytes(data []byte) error {
	// log.Default().Printf("Parsing raw event data (len=%d): %v\n", len(data), data)

	if len(data) < 25 {
		return fmt.Errorf("invalid data length: got %d, expected at least 25", len(data))
	}

	offset := 0

	srcIp, offset, err := parseIpFromBytes(data, offset)
	if err != nil {
		return err
	}

	dstIp, offset, err := parseIpFromBytes(data, offset)
	if err != nil {
		return err
	}

	ep.SourceIP = *srcIp
	ep.DestinationIP = *dstIp

	srcPort, offset, err := getPort(data, offset)
	if err != nil {
		return err
	}
	dstPort, offset, err := getPort(data, offset)
	if err != nil {
		return err
	}

	ep.SourcePort = srcPort
	ep.DestinationPort = dstPort

	ep.Protocol = Protocol(data[offset])
	ep.PacketLength = binary.LittleEndian.Uint32(data[offset+1 : offset+5])
	ep.Direction = uint8(data[offset+5])
	ep.Timestamp = time.Now()
	log.Default().Printf("Parsed event: %+v\n", ep)
	return nil
}

// Parse the IP from the ip_addr on xdp.c and return the new offset
func parseIpFromBytes(data []byte, offset int) (*netip.Addr, int, error) {
	srcIpFamily := data[offset]
	offset++

	ip := new(netip.Addr)
	switch srcIpFamily {
	case syscall.AF_INET:
		if len(data) < offset+4 {
			return nil, 0, fmt.Errorf("invalid IPv4 address")
		}

		dstIPBytes := [4]byte(data[offset : offset+4])
		// log.Default().Printf("Parsed IPv4 bytes: %v\n", dstIPBytes)

		ipv4 := netip.AddrFrom4(dstIPBytes)
		ip = &ipv4

	case syscall.AF_INET6:
		if len(data) < offset+16 {
			return nil, 0, fmt.Errorf("invalid IPv6 address")
		}
		ipv6Addr := [16]byte{}
		copy(ipv6Addr[:], data[offset:offset+16])
		ipv6 := netip.AddrFrom16(ipv6Addr)
		ip = &ipv6
	}

	// The union on the backend will always reserve at least 16 bytes for the IP,
	// so let's move the offset accordingly.
	offset += 16
	return ip, offset, nil
}

func getPort(data []byte, offset int) (uint16, int, error) {
	if len(data) < offset+2 {
		return 0, 0, fmt.Errorf("invalid port data")
	}
	port := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	return port, offset, nil
}
