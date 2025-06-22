package asn1plus

import (
	//"bytes"
	"testing"
)

func TestCER_codecov(_ *testing.T) {
	pkt := CER.New()
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	pkt.Type().OID()
	bts := make([]byte, 4)
	encodeCERLengthInto(&bts, -1)
}

func TestCERPacket_OutOfBoundsGuards(t *testing.T) {
	pkt := CER.New(0x02, 0x01, 0x00)
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
