package asn1plus

import (
	"bytes"
	"fmt"
	"testing"
)

func ExamplePacket_indefiniteLengthBERByOptions() {

	var oct OctetString = OctetString(`A really long value ...`)

	pkt, err := Marshal(oct,
		WithEncoding(BER),
		WithOptions(Options{
			Indefinite: true,
		}))

	if err != nil {
		fmt.Printf("Failed [BER encoding]: %v", err)
		return
	}

	fmt.Printf("%s\n", pkt.Hex())

	var oct2 OctetString
	if err = Unmarshal(pkt, &oct2); err != nil {
		fmt.Printf("Failed [BER decoding]: %v", err)
		return
	}

	fmt.Printf("Decoded %q\n", oct2)

	// Output: 04 80 41207265616C6C79206C6F6E672076616C7565202E2E2E0000
	// Decoded "A really long value ..."
}

func ExamplePacket_indefiniteLengthBERByStructFieldTag() {

	type MySequence struct {
		Value OctetString `asn1:"indefinite"`
	}

	mine := MySequence{OctetString(`A really long value ...`)}

	pkt, err := Marshal(mine, WithEncoding(BER))
	if err != nil {
		fmt.Printf("Failed [BER encoding]: %v", err)
		return
	}

	fmt.Printf("%s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2); err != nil {
		fmt.Printf("Failed [BER decoding]: %v", err)
		return
	}

	fmt.Printf("Decoded: %s\n", mine2.Value)

	// Output:
	// 30 1B 048041207265616C6C79206C6F6E672076616C7565202E2E2E0000
	// Decoded: A really long value ...
}

func TestBER_codecov(_ *testing.T) {
	pkt := &BERPacket{}
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
