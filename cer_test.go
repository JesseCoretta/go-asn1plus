//go:build !asn1_no_cer

package asn1plus

import (
	"bytes"
	"testing"
)

func TestCER_codecov(_ *testing.T) {
	pkt := CER.New()
	pkt.ID()
	pkt.Dump(nil)
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	pkt.Type().OID()
	pkt.Free()
	decodeCERLength([]byte{}, 10)
	decodeCERLength([]byte{0x82, 0x01}, 0)
	decodeCERLength([]byte{0x30, 0x00}, 0)
	decodeCERLength([]byte{0x80, 0x00}, 0)
	decodeCERLength([]byte{0x82, 0x01, 0xF4}, 0)
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

func TestCER_OctetStringCodecov(_ *testing.T) {
	oc := new(textCodec[OctetString])
	cpkt := &CERPacket{}
	_, _ = oc.write(cpkt, nil)
	cerSegmentedOctetStringWrite(oc, cpkt, nil)
	cpkt.offset = 100
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
	cpkt.data = nil
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
	cpkt.data = []byte{0x00}
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
}

func TestPDU_LargeOctetStringCER(t *testing.T) {
	var large OctetString = OctetString(strrpt("X", 2001)) // X*2001 times

	pkt, err := Marshal(large, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var alsoLarge OctetString
	if err = Unmarshal(pkt, &alsoLarge); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}

	want := large.Len()
	got := alsoLarge.Len()
	if want != got {
		t.Fatalf("%s failed [CER large OctetString size cmp.]:\n\twant: %d bytes\n\tgot:  %d bytes",
			t.Name(), want, got)
	}
}

func TestPDU_LargeBitStringCER(t *testing.T) {
	data := []byte(strrpt("Y", 2001))
	large := BitString{
		Bytes:     data,
		BitLength: len(data) * 8,
	}

	pkt, err := Marshal(large, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var alsoLarge BitString
	if err = Unmarshal(pkt, &alsoLarge); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}

	if large.BitLength != alsoLarge.BitLength {
		t.Fatalf("%s failed [CER large BitString size cmp.]:\n\twant: %d bits\n\tgot:  %d bits",
			t.Name(), large.BitLength, alsoLarge.BitLength)
	}

	if !bytes.Equal(large.Bytes, alsoLarge.Bytes) {
		t.Fatalf("%s failed [CER large BitString contents cmp.]: contents differ", t.Name())
	}
}
