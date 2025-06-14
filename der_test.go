package asn1plus

import (
	"testing"
)

func TestDER_codecov(_ *testing.T) {
	pkt := &DERPacket{}
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	bts := make([]byte, 4)
	encodeDERLengthInto(&bts, -1)
	encodeDERLengthInto(&bts, 501)
}

func TestDERPacket_OutOfBoundsGuards(t *testing.T) {
	pkt := DER.New(0x02, 0x01, 0x00)
	pkt.SetOffset(pkt.Len())

	if _, err := pkt.Class(); err != errorOutOfBounds {
		t.Fatalf("Class(): expected errorOutOfBounds, got %v", err)
	}

	if _, err := pkt.Tag(); err != errorOutOfBounds {
		t.Fatalf("Tag(): expected errorOutOfBounds, got %v", err)
	}

	if _, err := pkt.Compound(); err != errorOutOfBounds {
		t.Fatalf("Compound(): expected errorOutOfBounds, got %v", err)
	}
}
