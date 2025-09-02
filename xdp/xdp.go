package xdp

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jnfrati/xdp-inspector/types"
)

func StartXdpListener(ctx context.Context, ifname string, packetChan chan *types.EventPayload) {
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

				eventPayload := new(types.EventPayload)

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
