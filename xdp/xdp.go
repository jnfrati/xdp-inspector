package xdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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
	Timestamp       uint64
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
	ep.Timestamp = binary.LittleEndian.Uint64(data[offset+5 : offset+13])

	// log.Default().Printf("Parsed event: %+v\n", ep)
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

func StartXdpListener(ctx context.Context, packetChan chan *EventPayload) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "eno1" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach xdp_prog_func to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPacketObserver,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	rb, err := ringbuf.NewReader(objs.XdpPacketEvents)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %s", err)
	}

	defer rb.Close()

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Read from the ring buffer.
				event, err := rb.Read()
				if err != nil {
					log.Printf("reading ringbuf: %s", err)
					continue
				}

				eventPayload := new(EventPayload)

				eventPayload.FromBytes(event.RawSample)

				packetChan <- eventPayload
			}
		}
	}()

	for {
		select {
		case <-tick:

			iter := objs.XdpStatsMap.Iterate()
			entries := 0
			for {
				sourceIp := uint32(0)
				packetsReceived := uint32(0)
				ok := iter.Next(&sourceIp, &packetsReceived)
				if !ok {
					break
				}
				// Convert IP to readable format
				ip := net.IPv4(
					byte(sourceIp),
					byte(sourceIp>>8),
					byte(sourceIp>>16),
					byte(sourceIp>>24),
				)

				log.Printf("  %s: %d packets", ip.String(), packetsReceived)
				entries++
			}

			log.Printf("Total entries: %d", entries)
		case <-ctx.Done():
			log.Print("Received signal, exiting..")
			return
		}
	}
}
