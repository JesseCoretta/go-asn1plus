//go:build !asn1_no_der

package asn1plus

import (
	"testing"
)

func TestDER_codecov(_ *testing.T) {
	pkt := &DERPacket{}
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	bts := make([]byte, 4)
	encodeBCDLengthInto(&bts, -1)
	encodeBCDLengthInto(&bts, 501)
	tlvVerifyLengthState(&DERPacket{offset: 1}, []byte{0xa, 0x80, 0x83, 0x01, 0xe4})
	tlvVerifyLengthState(&DERPacket{offset: 1}, []byte{0xa, 0x03, 0x83, 0x01, 0xe4})
	tlvVerifyLengthState(&DERPacket{offset: 1}, []byte{0x04, 0x82, 0x00, 0x80, 0x83, 0x01, 0xe4, 0x1e, 0x2a})
	tlvVerifyLengthState(&DERPacket{offset: 1}, []byte{0x02, 0x81, 0x7F, 0x83, 0x01, 0xe4, 0x1e, 0x2a})
	writeTLV(&DERPacket{}, TLV{Length: -1}, &Options{Indefinite: true})
	marshalCheckBadOptions(DER, &Options{Indefinite: true})
}

func TestParseBodyCornerCases_DER(t *testing.T) {
	tests := []struct {
		name string
		der  bool   // true→DER, false→BER
		data []byte // full packet bytes
		exp  error
	}{
		{
			"indefinite length in DER is illegal",
			true,
			[]byte{0x30, 0x80, 0x00, 0x00}, // SEQUENCE, indefinite, empty
			errorIndefiniteProhibited,
		},
	}

	for _, tc := range tests {
		_, err := parseBody(tc.data, 0, DER)
		if !errorsEqual(err, tc.exp) {
			t.Errorf("%s: got err=%v want=%v", tc.name, err, tc.exp)
		}
	}
}

func TestParseFullBytesCornerCases_DER(t *testing.T) {
	tests := []struct {
		name string
		typ  EncodingRule
		data []byte
		exp  error
	}{
		{
			"DER with indefinite length",
			DER,
			[]byte{0x30, 0x80, 0x00, 0x00},
			errorIndefiniteProhibited,
		},
	}

	for _, tc := range tests {
		_, err := parseFullBytes(tc.data, 0, tc.typ)
		if !errorsEqual(err, tc.exp) {
			t.Errorf("%s: got err=%v want=%v", tc.name, err, tc.exp)
		}
	}
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
