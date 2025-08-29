package db

import (
	"log"
	"os"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
	"github.com/jnfrati/xdp-inspector/xdp"
)

func GetSchema() *arrow.Schema {
	return arrow.NewSchema([]arrow.Field{
		{Name: "source_ip", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "destination_ip", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "source_port", Type: arrow.PrimitiveTypes.Uint16, Nullable: true},
		{Name: "destination_port", Type: arrow.PrimitiveTypes.Uint16, Nullable: true},
		{Name: "protocol", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "packet_length", Type: arrow.PrimitiveTypes.Uint32, Nullable: true},
		{Name: "timestamp", Type: arrow.FixedWidthTypes.Timestamp_ms, Nullable: true},
	}, nil)
}

func Insert(writer *pqarrow.FileWriter, packet *xdp.EventPayload) error {
	b := array.NewRecordBuilder(memory.NewGoAllocator(), GetSchema())
	defer b.Release()

	b.Field(0).(*array.StringBuilder).Append(packet.SourceIP.String())
	b.Field(1).(*array.StringBuilder).Append(packet.DestinationIP.String())
	b.Field(2).(*array.Uint16Builder).Append(packet.SourcePort)
	b.Field(3).(*array.Uint16Builder).Append(packet.DestinationPort)
	b.Field(4).(*array.StringBuilder).Append(packet.Protocol.String())
	b.Field(5).(*array.Uint32Builder).Append(packet.PacketLength)
	b.Field(6).(*array.TimestampBuilder).Append(arrow.Timestamp(packet.Timestamp))

	rec := b.NewRecord()
	defer rec.Release()

	if err := writer.Write(rec); err != nil {
		return err
	}

	log.Println("Wrote packets.parquet")
	return nil
}

func InsertBatch(writer *pqarrow.FileWriter, packets []*xdp.EventPayload) error {
	b := array.NewRecordBuilder(memory.NewGoAllocator(), GetSchema())
	defer b.Release()

	b.Field(0).(*array.StringBuilder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) string {
		return p.SourceIP.String()
	}), nil)
	b.Field(1).(*array.StringBuilder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) string {
		return p.DestinationIP.String()
	}), nil)
	b.Field(2).(*array.Uint16Builder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) uint16 {
		return p.SourcePort
	}), nil)
	b.Field(3).(*array.Uint16Builder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) uint16 {
		return p.DestinationPort
	}), nil)
	b.Field(4).(*array.StringBuilder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) string {
		return p.Protocol.String()
	}), nil)
	b.Field(5).(*array.Uint32Builder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) uint32 {
		return p.PacketLength
	}), nil)
	b.Field(6).(*array.TimestampBuilder).AppendValues(ReduceFromField(packets, func(p *xdp.EventPayload) arrow.Timestamp {
		return arrow.Timestamp(p.Timestamp)
	}), nil)

	rec := b.NewRecord()
	defer rec.Release()

	if err := writer.Write(rec); err != nil {
		return err
	}

	log.Println("Wrote packets.parquet")
	return nil

}

func ReduceFromField[T any](packets []*xdp.EventPayload, fieldFunc func(*xdp.EventPayload) T) []T {
	var reduced []T
	for _, packet := range packets {
		fieldValue := fieldFunc(packet)
		reduced = append(reduced, fieldValue)
	}
	return reduced
}

func InitParquetWriter() (*pqarrow.FileWriter, error) {
	f, err := os.Create("packets.parquet")
	if err != nil {
		return nil, err
	}

	writer, err := pqarrow.NewFileWriter(GetSchema(), f, nil, pqarrow.NewArrowWriterProperties())
	if err != nil {
		return nil, err
	}

	return writer, nil
}
