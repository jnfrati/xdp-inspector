package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jnfrati/xdp-inspector/db"
	"github.com/jnfrati/xdp-inspector/xdp"
)

const BUF_SIZE = 100

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	w, err := db.InitParquetWriter()
	if err != nil {
		log.Fatalf("Couldn't init parquet writer: %v", err)
	}
	defer w.Close()

	packetChan := make(chan *xdp.EventPayload, 10000)
	go xdp.StartXdpListener(ctx, packetChan)

	go func() {
		fmt.Println("Starting packet processor...")

		buf := make([]*xdp.EventPayload, 0, BUF_SIZE)
		for {
			select {
			case event := <-packetChan:
				log.Default().Print("Buf full, inserting batch...")
				if err := db.Insert(w, event); err != nil {
					log.Printf("Error inserting packet batch: %v", err)
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
