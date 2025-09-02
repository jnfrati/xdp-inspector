package tc

import (
	"context"
	"log"
	"net"

	"github.com/cockroachdb/errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jnfrati/xdp-inspector/types"
)

func StartTrafficControlEngressObserver(ctx context.Context, ifname string, packetChan chan *types.EventPayload) error {

	if err := features.HaveProgramType(ebpf.SchedCLS); errors.Is(err, ebpf.ErrNotSupported) {
		return errors.Wrap(err, "tc egress observer cannot start")
	}

	var objs tcObjects
	if err := loadTcObjects(&objs, nil); err != nil {
		return errors.Wrap(err, "cannot start tc egress observer, couldn't load tcobjs")
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return errors.Wrap(err, "couldn't start tc egress observer, couldn't get iface by name")
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgressObserver,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return errors.Wrap(err, "couldn't start tc egress observer, couldn't attach tcx program")
	}
	defer link.Close()

	rb, err := ringbuf.NewReader(objs.EgressPacketEvents)
	if err != nil {
		return errors.Wrap(err, "closing tc egress observer, couldn't create ringbuff reader")
	}

	for {
		select {
		case <-ctx.Done():
			return nil

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
}
