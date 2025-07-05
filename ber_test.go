package asn1plus

import "testing"

func TestBER_codecov(_ *testing.T) {
	pkt := BER.New()
	pkt.HasMoreData()
	pkt.WriteTLV(TLV{Tag: 3, Class: 1})
	bts := make([]byte, 4)
	encodeBERLengthInto(&bts, -1)
}

func TestParseBodyCornerCases_BER(t *testing.T) {
	tests := []struct {
		name string
		data []byte // full packet bytes
		exp  error
	}{
		{
			"empty slice",
			nil,
			errorEmptyIdentifier,
		},
		{
			"definite length but truncated content",
			[]byte{0x02, 0x02, 0x01}, // INTEGER, len=2, only 1 byte present
			errorTruncatedContent,
		},
		{
			"BER indefinite missing EOC",
			[]byte{0x30, 0x80, 0x02, 0x01, 0x00}, // no 00 00 terminator
			errorTruncatedContent,
		},
	}

	for _, tc := range tests {
		_, err := parseBody(tc.data, 0, BER)
		if !errorsEqual(err, tc.exp) {
			t.Errorf("%s: got err=%v want=%v", tc.name, err, tc.exp)
		}
	}
}

func TestParseFullBytesCornerCases_BER(t *testing.T) {
	tests := []struct {
		name string
		typ  EncodingRule
		data []byte
		exp  error
	}{
		{
			"definite length but packet truncated",
			BER,
			[]byte{0x04, 0x03, 0x61, 0x62}, // OCTET STRING, len=3, only 2 bytes
			errorTruncatedContent,
		},
		{
			"BER indefinite missing EOC",
			BER,
			[]byte{0x30, 0x80, 0x02, 0x01, 0x00},
			errorTruncatedContent,
		},
	}

	for _, tc := range tests {
		_, err := parseFullBytes(tc.data, 0, tc.typ)
		if !errorsEqual(err, tc.exp) {
			t.Errorf("%s: got err=%v want=%v", tc.name, err, tc.exp)
		}
	}
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
