package asn1plus

import (
	"bytes"
	"testing"
)

func TestBER_codecov(_ *testing.T) {
	pkt := BER.New()
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	bts := make([]byte, 4)
	encodeBERLengthInto(&bts, -1)
	readIndefiniteContents([]byte{0x1, 0x2, 0x3, 0x4, 0x5}, 2)
}

func TestBERPacket_OutOfBoundsGuards(t *testing.T) {
	pkt := BER.New(0x02, 0x01, 0x00)
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

func TestBERReadIndefiniteContents_Success(t *testing.T) {
	/*
	   Stream layout:  [DE AD BE EF] 00 00 FF
	                   ^offset=0        ^extra byte just to ensure we stop early
	*/
	stream := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0xFF}

	contents, newOff, err := readIndefiniteContents(stream, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(contents, want) {
		t.Fatalf("content mismatch: got % X want % X", contents, want)
	}

	if newOff != 6 {
		t.Fatalf("newOffset mismatch: got %d want 6", newOff)
	}
}
