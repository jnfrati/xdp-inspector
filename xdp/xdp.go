package xdp

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func Start() {
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
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
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
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
