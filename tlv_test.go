package asn1plus

import "testing"

func TestTLVEqual_BER(t *testing.T) {
	a := TLV{
		typ:      BER,
		Class:    0,
		Tag:      4,
		Compound: false,
		Length:   6,
		Value:    []byte("Hello0"),
	}
	b := TLV{
		typ:      BER,
		Class:    0,
		Tag:      4,
		Compound: false,
		Length:   6,
		Value:    []byte("Hello0"),
	}
	if !a.Eq(b, true) {
		t.Errorf("Expected equal BER TLVs, but they differed")
	}

	// Now change length and require length check.
	b.Length = 7
	if a.Eq(b, true) {
		t.Errorf("Expected BER TLVs to differ when length does not match")
	}
}

func TestTLVEncode(t *testing.T) {
	a := TLV{
		typ:      BER,
		Class:    0,
		Tag:      4,
		Compound: false,
		Length:   6,
		Value:    []byte("Hello0"),
	}
	_ = a.String()

	encoded := encodeTLV(a, nil)
	// Expect: identifier octet: 0x04 (0<<6 | 0x04), then length 0x06, then "Hello0".
	expected := append([]byte{0x04, 0x06}, []byte("Hello0")...)
	if !deepEq(encoded, expected) {
		t.Errorf("TLV Encode() = %x; want %x", encoded, expected)
	}
}

func TestGetTLV(t *testing.T) {
	// Encode a TLV: identifier 0x04, length 0x06, value "Hello0".
	data := append([]byte{0x04, 0x06}, []byte("Hello0")...)
	pkt := &BERPacket{
		data:   data,
		offset: 0,
	}
	tlv, err := pkt.TLV()
	if err != nil {
		t.Fatalf("berGetTLV error: %v", err)
	}
	if tlv.Class != 0 || tlv.Tag != 4 || tlv.Compound != false || tlv.Length != 6 {
		t.Errorf("getTLV returned incorrect fields: got class=%d tag=%d compound=%t length=%d",
			tlv.Class, tlv.Tag, tlv.Compound, tlv.Length)
	}
	// The value should come from the packet data starting at the current offset.
	if string(tlv.Value[:6]) != "Hello0" {
		t.Errorf("getTLV value = %s; want %s", string(tlv.Value[:6]), "Hello0")
	}
}

func TestBERWriteTLV(t *testing.T) {
	pkt := &BERPacket{
		data:   []byte{},
		offset: 0,
	}
	tlv := TLV{
		typ:      BER,
		Class:    0,
		Tag:      4,
		Compound: false,
		Length:   5,
		Value:    []byte("Hello"),
	}
	if err := writeTLV(pkt, tlv, nil); err != nil {
		t.Fatalf("writeTLV error: %v", err)
	}
	expected := encodeTLV(tlv, nil)
	if !deepEq(pkt.data, expected) {
		t.Errorf("berWriteTLV: pkt.data = %x; want %x", pkt.data, expected)
	}
	if pkt.Offset() != len(pkt.data) {
		t.Errorf("berWriteTLV: pkt.Offset() = %d; expected %d", pkt.Offset(), len(pkt.data))
	}
}

func TestReadBase128Int(t *testing.T) {
	// For the number 300, we expect base-128 encoding to be {0x82, 0x2C}.
	data := []byte{0x82, 0x2C}
	pkt := &BERPacket{
		data:   data,
		offset: 0,
	}
	n, err := readBase128Int(pkt)
	if err != nil {
		t.Errorf("readBase128Int error: %v", err)
	}
	if n != 300 {
		t.Errorf("readBase128Int = %d; want 300", n)
	}
}

func testWantSub(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !cntns(err.Error(), sub) {
		t.Fatalf("expected error containing %q, got %v", sub, err)
	}
}

func TestGetTLV_NoDataAtOffset(t *testing.T) {
	pkt := BER.New(0x02, 0x01, 0x00)
	pkt.SetOffset(pkt.Len())

	_, err := getTLV(pkt, nil)
	testWantSub(t, err, "no data available")
}

func TestGetTLV_BadTagIdentifier(t *testing.T) {
	pkt := BER.New(0x1F, 0x80)

	_, _ = getTLV(invalidPacket{}, nil)
	_, err := getTLV(pkt, nil)
	testWantSub(t, err, "BER PDU.TLV: error reading length: length bytes not found")
}

func TestGetTLV_ExplicitButPrimitive(t *testing.T) {
	pkt := BER.New(0x02, 0x01, 0x09)

	opts := &Options{Explicit: true}
	opts.SetTag(3)
	opts.SetClass(0)

	_, err := getTLV(pkt, opts)
	testWantSub(t, err, "Expected constructed TLV for explicit tagging")
}

func TestGetTLV_BadLengthHeader(t *testing.T) {
	pkt := BER.New(0x02, 0x82)

	_, err := getTLV(pkt, nil)
	testWantSub(t, err, "error reading length:")
}

func TestGetTLV_TagClassOverrideSuccess(t *testing.T) {
	/*
	   SEQUENCE {
	     INTEGER 0
	   }

	   Encoded: 30 03 02 01 00
	            └─┬┘ └┬┘ └┬┘
	              │   │   └── INTEGER 0
	              │   └────── length = 3
	              └────────── constructed SEQUENCE (compound = true)
	*/
	pkt := BER.New(
		0x30, 0x03, // SEQUENCE, length 3
		0x02, 0x01, 0x00, // INTEGER 0
	)
	pkt.SetOffset(0)

	// Supply an *implicit* (Explicit=false) override so that the class/tag
	// replacement path runs.
	opts := &Options{}
	opts.SetClass(2)
	opts.SetTag(5)

	tlv, err := getTLV(pkt, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tlv.Class != 2 || tlv.Tag != 5 {
		t.Fatalf("override failed: got (class:%d, tag:%d), want (2,5)",
			tlv.Class, tlv.Tag)
	}
}

func TestGetTLV_ErrorReadingTag(t *testing.T) {
	tmpBuf := getBuf()
	defer putBuf(tmpBuf)
	pkt := BER.New((*tmpBuf)...)
	pkt.Append(0x1F)

	_, err := getTLV(pkt, nil)
	if err == nil || !cntns(err.Error(), "error reading tag") {
		t.Fatalf("%s failed: expected tag-parse error, got %v", t.Name(), err)
	}
}

func TestGetTLV_InvalidPacket(t *testing.T) {
	pkt := invalidPacket{}
	if _, err := getTLV(pkt, nil); err == nil {
		t.Fatalf("%s failed: expected error, got nil", t.Name())
	}
}

func TestGetTLV_ParseClassIdentifierError(t *testing.T) {
	pkt := &testPacket{
		data:   []byte{},
		offset: 0,
		length: 1,
	}

	_, err := getTLV(pkt, nil)
	if err == nil || err.Error() != errorEmptyIdentifier.Error() {
		t.Fatalf("expected errorEmptyIdentifier, got %v", err)
	}
}

func TestGetTLV_UnsupportedEncodingRule(t *testing.T) {
	// Minimal correct TLV: SEQUENCE {}, definite length 0
	d := []byte{0x30, 0x00}

	pkt := &testPacket{
		data:   d,
		offset: 0,
		length: len(d), // honest length
		typ:    18,     // 18 ⇒ neither BER nor DER → default case
	}

	_, err := getTLV(pkt, nil)
	expect := errorRuleNotImplemented.Error()
	if err == nil || err.Error() != expect {
		t.Fatalf("expected '%s', got %v", expect, err)
	}
}

func TestEncodeBase128Int_ContinuationBit(t *testing.T) {
	out := encodeBase128Int(200) // requires two base-128 octets (200 = 0x81 0x48)

	if len(out) != 2 {
		t.Fatalf("expected 2-byte result, got %d bytes", len(out))
	}
	if out[0]&0x80 == 0 { // first byte must have MSB set
		t.Fatalf("continuation bit not set on first byte: %02X", out[0])
	}
	if out[1]&0x80 != 0 { // last byte must *not* have MSB set
		t.Fatalf("continuation bit wrongly set on final byte: %02X", out[1])
	}
}

func TestReadBase128Int_Truncated(t *testing.T) {
	empty := BER.New()
	_, err := readBase128Int(empty)
	if err == nil || !cntns(err.Error(), "truncated base-128 integer") {
		t.Fatalf("expected truncated-integer error, got %v", err)
	}
}

func TestEncodeTLV_ExplicitSetsCompound(t *testing.T) {
	// Primitive TLV we will *implicitly* wrap: UNIVERSAL, tag=4 (OCTET STRING)
	tlv := TLV{
		Class:    0,
		Tag:      4,
		Length:   1,
		Compound: false,
		Value:    []byte{0xAA},
	}

	opts := &Options{}
	opts.SetClass(2)
	opts.SetTag(3)
	opts.Explicit = true
	out := encodeTLV(tlv, opts)

	// First identifier octet must now carry bit-6 (0x20) = “constructed”.
	if out[0]&0x20 == 0 {
		t.Fatalf("constructed bit not set; got first byte 0x%02X", out[0])
	}
}

func TestEncodeTLV_PanicsOnNegativeTag(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	encodeTLV(TLV{Tag: -1}, nil)
}

func TestEncodeTLV_codecov(t *testing.T) {
	encodeTLV(TLV{typ: BER, Tag: 3, Class: 1}, &Options{Indefinite: true})
	tlvVerifyLengthState(&BERPacket{offset: 1}, []byte{0xa, 0x80, 0x83, 0x01, 0xe4})
	tlvVerifyLengthState(&BERPacket{offset: 1}, []byte{0xa, 0x03, 0x83, 0x01, 0xe4})
	tlvVerifyLengthState(&BERPacket{offset: 1}, []byte{0x04, 0x82, 0x00, 0x80, 0x83, 0x01, 0xe4, 0x1e, 0x2a})
	tlvVerifyLengthState(&BERPacket{offset: 1}, []byte{0x02, 0x81, 0x7F, 0x83, 0x01, 0xe4, 0x1e, 0x2a})
	writeTLV(&BERPacket{}, TLV{Length: -1}, &Options{Indefinite: true})
}
