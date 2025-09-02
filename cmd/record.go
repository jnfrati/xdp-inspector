package cmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jnfrati/xdp-inspector/db"
	"github.com/jnfrati/xdp-inspector/tc"
	"github.com/jnfrati/xdp-inspector/types"
	"github.com/jnfrati/xdp-inspector/xdp"
	"github.com/spf13/cobra"
)

const BUF_SIZE = 100

func RecordCommand() *cobra.Command {
	recordCmd := &cobra.Command{
		Use:   "record",
		Short: "record network traffic",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			// Your command logic here
			output, _ := cmd.Flags().GetString("output")
			iface, _ := cmd.Flags().GetString("interface")
			duration, _ := cmd.Flags().GetString("duration")

			record(cmd.Context(), output, iface, duration)
		},
	}

	recordCmd.Flags().String("output", "output.parquet", "Output file for recorded traffic")
	recordCmd.Flags().String("interface", "eth0", "Network interface to attach XDP program to")
	recordCmd.Flags().String("duration", "30s", "Duration for recording traffic")
	return recordCmd
}

func record(ctx context.Context, output string, iface string, duration string) {
	dt, err := time.ParseDuration(duration)
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}

	if dt.Seconds() < 10 {
		log.Fatalf("Duration must be at least 10 seconds")
	}

	// Set a timeout for the recording
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, dt)
	defer cancel()

	w, err := db.InitParquetWriter(output)
	if err != nil {
		log.Fatalf("Couldn't init parquet writer: %v", err)
	}
	defer w.Close()

	ingressChan := make(chan *types.EventPayload, 10000)
	go xdp.StartXdpListener(ctx, iface, ingressChan)

	egressChan := make(chan *types.EventPayload, 10000)
	go func() {
		err := tc.StartTrafficControlEngressObserver(ctx, iface, egressChan)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}()

	go func() {
		fmt.Println("Starting packet processor...")

		buf := make([]*types.EventPayload, 0, BUF_SIZE)
		for {
			select {
			case event := <-ingressChan:
				log.Default().Print("Buf full, inserting batch...")
				if err := db.Insert(w, event); err != nil {
					log.Printf("Dropping packet, couldn't store: %v", err)
				}
			case event := <-egressChan:
				log.Printf("parsing egress")
				if err := db.Insert(w, event); err != nil {
					log.Printf("Dropping packet, couldn't store: %v", err)
				}
			case <-ctx.Done():
				if len(buf) > 0 {
					if err := db.InsertBatch(w, buf); err != nil {
						log.Printf("Error inserting final packet batch: %v", err)
					}
				}
				return
			}
		}
	}()

	<-ctx.Done()
	fmt.Println("Shutting down...")
}
