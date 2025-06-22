package asn1plus

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

/*
testPacket implements an invalid-ish Packet qualifier used
solely for tripping special corner-cases in unit tests.
*/
type testPacket struct {
	data   []byte
	offset int
	length int          // reported Len(); can differ from len(data)
	typ    EncodingRule // hardwire a type
}

func (r testPacket) Data() []byte                  { return r.data }
func (r testPacket) Offset() int                   { return r.offset }
func (r *testPacket) SetOffset(i ...int)           { setPacketOffset(r, i...) }
func (r testPacket) Len() int                      { return r.length }
func (r testPacket) Type() EncodingRule            { return r.typ }
func (r testPacket) Hex() string                   { return formatHex(r) }
func (r *testPacket) HasMoreData() bool            { return r.offset < len(r.data) }
func (r *testPacket) TLV() (TLV, error)            { return getTLV(r, nil) }
func (r *testPacket) WriteTLV(tlv TLV) error       { return writeTLV(r, tlv, nil) }
func (r *testPacket) Packet(L int) (Packet, error) { return extractPacket(r, L) }

func (r *testPacket) Bytes() ([]byte, error) {
	return parseBody(r.Data(), r.Offset(), r.Type())
}

func (r *testPacket) FullBytes() ([]byte, error) {
	return parseFullBytes(r.Data(), r.Offset(), r.Type())
}

func (r *testPacket) Append(data ...byte) {
	if r == nil || len(data) == 0 {
		return
	}
	need := len(r.data) + len(data)

	if cap(r.data) < need {
		bufPtr := bufPool.Get().(*[]byte)
		if cap(*bufPtr) < need {
			*bufPtr = make([]byte, 0, need*2)
		}
		newBuf := append((*bufPtr)[:0], r.data...)

		if cap(r.data) != 0 {
			old := r.data[:0]
			bufPool.Put(&old)
		}
		r.data = newBuf
	}

	r.data = append(r.data, data...)
}

func (r *testPacket) Free() {
	if cap(r.data) != 0 {
		buf := r.data[:0]
		bufPool.Put(&buf)
	}
	*r = testPacket{}
	testPktPool.Put(r)
}

func (r *testPacket) PeekTLV() (TLV, error) {
	sub := r.Type().New(r.Data()...)
	sub.SetOffset(r.Offset())
	return getTLV(sub, nil)
}

func (r *testPacket) Compound() (bool, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return false, errorOutOfBounds
	}
	return parseCompoundIdentifier(buf[r.Offset():])
}

func (r *testPacket) Class() (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	return parseClassIdentifier(buf[r.Offset():])
}

func (r *testPacket) Tag() (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	tag, _, err := parseTagIdentifier(buf[r.Offset():])
	return tag, err
}

/*
This example demonstrates the manual creation of a [Packet] instance using
pre-encoded bytes as input.
*/
func ExamplePacket_manualCreation() {
	// For the purposes of this example, we chose BER to
	// encode a UTF-8 string.
	berBytes := []byte{
		0x0c, 0x16, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
		0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
	}

	tmpBuf := getBuf()
	defer putBuf(tmpBuf)
	pkt := BER.New((*tmpBuf)...)
	pkt.Append(berBytes...)

	var u8 UTF8String

	if err := Unmarshal(pkt, &u8); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(u8)
	// Output: this is a UTF-8 string
}

func TestPacket_invalidPacket(_ *testing.T) {
	var invp invalidPacket
	invp.Type()
	invp.Data()
	invp.Offset()
	invp.Packet(0)
	invp.SetOffset(1)
	invp.Free()
	invp.Bytes()
	invp.FullBytes()
	invp.HasMoreData()
	invp.Class()
	invp.Compound()
	invp.Tag()
	_ = invp.Hex()
	invp.Len()
	invp.Append(0x0)
	invp.PeekTLV()
	invp.TLV()
	invp.WriteTLV(TLV{})
}

func TestPacket_PeekTLV(t *testing.T) {
	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
	}

	mine := MySequence{OctetString(`Hello`), PrintableString(`World`)}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		} else if _, err = pkt.PeekTLV(); err != nil {
			t.Fatalf("%s failed [%s PeekTLV]: %v", t.Name(), rule, err)
		}
	}
}

func TestPacket_Packet(t *testing.T) {
	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
	}

	mine := MySequence{OctetString(`Hello`), PrintableString(`World`)}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var next TLV
		if next, err = pkt.TLV(); err != nil {
			t.Fatalf("%s failed [%s TLV]: %v", t.Name(), rule, err)
		}

		//var sub Packet
		if _, err = pkt.Packet(next.Length); err != nil {
			t.Fatalf("%s failed [%s PeekTLV]: %v", t.Name(), rule, err)
		}
	}
}

func TestPacket_RawValueCompatSequence(t *testing.T) {
	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
	}

	mine := MySequence{OctetString(`Hello`), PrintableString(`World`)}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var (
			b, fb []byte
			tag,
			class int
			cmpnd bool
		)

		if class, err = pkt.Class(); err != nil {
			t.Fatalf("%s failed [%s Class()]: %v", t.Name(), rule, err)
		}

		if tag, err = pkt.Tag(); err != nil {
			t.Fatalf("%s failed [%s Tag()]: %v", t.Name(), rule, err)
		}

		if cmpnd, err = pkt.Compound(); err != nil {
			t.Fatalf("%s failed [%s Compound()]: %v", t.Name(), rule, err)
		}

		if b, err = pkt.Bytes(); err != nil {
			t.Fatalf("%s failed [%s Bytes()]: %v", t.Name(), rule, err)
		}

		if fb, err = pkt.FullBytes(); err != nil {
			t.Fatalf("%s failed [%s FullBytes()]: %v", t.Name(), rule, err)
		}

		if class != 0 || tag != 16 || !cmpnd {
			t.Fatalf("%s failed [RawValue cmp.]: tag, class or compound mismatch", t.Name())
		}

		if len(b) != 14 || len(fb) != 16 {
			t.Fatalf("%s failed [RawValue cmp.]: unexpected payload sizes\n\twant: b:14,fb:16\n\tgot:  b:%d,fb:%d",
				t.Name(), len(b), len(fb))
		}
	}
}

func TestPacket_codecov(_ *testing.T) {
	findEOC([]byte{0x14, 0x33})
	formatHex([]byte{})
	pktB := &BERPacket{}
	pktB.Type().OID()
	pktD := &DERPacket{}
	pktD.Type().OID()
	With(&Options{})
	x := WithEncoding(DER)
	x(&encodingConfig{})
	x = WithOptions(Options{})
	x(&encodingConfig{})
	tester := testPacket{}
	tester.Type().New()
	tester.HasMoreData()

	Marshal(nil)
	var slice []int
	Marshal(slice)
	Marshal(&slice)
	slice = []int{1, 2, 3}
	Marshal(slice)
	Marshal(&slice)

	Unmarshal(&BERPacket{}, nil)
	opts := Options{}
	opts.SetClass(3)
	opts.SetTag(26)
	Unmarshal(&BERPacket{}, &struct{}{}, With(opts))
	var value *EmbeddedPDV
	unmarshalValue(&BERPacket{}, reflect.ValueOf(value), nil)

	opts.SetTag(4)
	opts.SetClass(3)
	marshalPrepareSpecialOptions(EmbeddedPDV{}, &opts)
	checkBadMarshalOptions(DER, &Options{Indefinite: true})

	marshalValue(refValueOf(nil), &BERPacket{}, nil, 0)
	var nill *struct{}
	marshalValue(refValueOf(nill), &BERPacket{}, nil, 0)
	marshalValue(refValueOf(OctetString("test")), &BERPacket{}, nil, 0)
	marshalValue(refValueOf(Choice{Value: nil, Explicit: true}), &BERPacket{}, nil, 0)

	unmarshalHandleTag("octet", &BERPacket{}, &TLV{Tag: 4, Length: 4000}, &opts)
	berBytes := []byte{
		0x0c, 0x16, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
		0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
	}

	o := OctetString("test")
	unmarshalPrimitive(&BERPacket{data: berBytes}, refValueOf(&o), &opts)

	BER.Extends(CER)
}

func TestParseLengthCornerCases(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expLen int
		expLL  int
		expErr error
	}{
		{"empty", nil, 0, 0, errorEmptyLength},
		{"truncated long-form header", []byte{0x82}, 0, 0, errorTruncatedLength},
		// n = 5 ⇒ > 4 octets not allowed (over 32-bit cap)
		{"too-large long-form", []byte{0x85, 1, 2, 3, 4, 5}, 0, 0, errorLengthTooLarge},
		// Valid short-form should *not* fail (guard sanity)
		{"legal short-form", []byte{0x7F}, 0x7F, 1, nil},
		// Legal long-form (0x0100 = 256)
		{"legal long-form", []byte{0x82, 0x01, 0x00}, 256, 3, nil},
	}

	for _, tc := range tests {
		l, ll, err := parseLength(tc.input)
		if l != tc.expLen || ll != tc.expLL || !errorsEqual(err, tc.expErr) {
			t.Errorf("%s: got (len=%d,lenLen=%d,err=%v) want (len=%d,lenLen=%d,err=%v)",
				tc.name, l, ll, err, tc.expLen, tc.expLL, tc.expErr)
		}
	}
}

func TestParseTagIdentifierCornerCases(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		expTag, expL int
		expErr       error
	}{
		{"empty", nil, 0, 0, errorEmptyIdentifier},
		{
			"tag too large (5 continuation bytes)",
			// 0x1F opens high-tag, then five bytes with MSB 1 ⇒ overflow
			[]byte{0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
			0, 0, errorTagTooLarge,
		},
		{
			"truncated tag (no terminating MSB-0 byte)",
			[]byte{0x1F, 0x80},
			0, 0, errorTruncatedTag,
		},
	}

	for _, tc := range tests {
		tag, l, err := parseTagIdentifier(tc.input)
		if tag != tc.expTag || l != tc.expL || !errorsEqual(err, tc.expErr) {
			t.Errorf("%s: got(tag=%d,len=%d,err=%v) want(tag=%d,len=%d,err=%v)",
				tc.name, tag, l, err, tc.expTag, tc.expL, tc.expErr)
		}
	}
}

func TestParseBodyCornerCases(t *testing.T) {
	tests := []struct {
		name string
		der  bool   // true→DER, false→BER
		data []byte // full packet bytes
		exp  error
	}{
		{
			"empty slice",
			false,
			nil,
			errorEmptyIdentifier,
		},
		{
			"definite length but truncated content",
			false,
			[]byte{0x02, 0x02, 0x01}, // INTEGER, len=2, only 1 byte present
			errorTruncatedContent,
		},
		{
			"indefinite length in DER is illegal",
			true,
			[]byte{0x30, 0x80, 0x00, 0x00}, // SEQUENCE, indefinite, empty
			errorIndefiniteProhibited,
		},
		{
			"BER indefinite missing EOC",
			false,
			[]byte{0x30, 0x80, 0x02, 0x01, 0x00}, // no 00 00 terminator
			errorTruncatedContent,
		},
	}

	for _, tc := range tests {
		enc := BER
		if tc.der {
			enc = DER
		}
		_, err := parseBody(tc.data, 0, enc)
		if !errorsEqual(err, tc.exp) {
			t.Errorf("%s: got err=%v want=%v", tc.name, err, tc.exp)
		}
	}
}

func TestParseFullBytesCornerCases(t *testing.T) {
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

func TestFindEOCCornerCases(t *testing.T) {
	// Outer SEQUENCE (0x30, indefinite)
	//   Inner SET (0x31, indefinite)
	//     INTEGER (0x02,1,0)
	//   ... *missing* both inner & outer 00 00
	stream := []byte{0x30, 0x80, 0x31, 0x80, 0x02, 0x01, 0x00}

	if _, err := findEOC(stream); !errorsEqual(err, errorTruncatedContent) {
		t.Fatalf("findEOC: expected errorTruncatedContent, got %v", err)
	}
}

func TestIdentifierHelpersEmptySlice(t *testing.T) {
	if cls, err := parseClassIdentifier(nil); cls != -1 || !errorsEqual(err, errorEmptyIdentifier) {
		t.Errorf("parseClassIdentifier: got (cls=%d,err=%v) want (-1,%v)", cls, err, errorEmptyIdentifier)
	}

	if c, err := parseCompoundIdentifier(nil); c || !errorsEqual(err, errorEmptyIdentifier) {
		t.Errorf("parseCompoundIdentifier: got (compound=%v,err=%v) want (false,%v)", c, err, errorEmptyIdentifier)
	}
}

func TestFormatHexCornerCases(t *testing.T) {
	if got := formatHex([]byte{}); got != "" {
		t.Errorf("empty slice: expected \"\", got %q", got)
	}

	// Only a multi-octet tag, no length/content.  Should gracefully emit the tag
	// itself and nothing crash.
	tagOnly := []byte{0x1F, 0x83, 0x7F}
	want := bytes.ToUpper([]byte(hexstr(tagOnly)))
	if got := formatHex(tagOnly); !bytes.Equal([]byte(got), want) {
		t.Errorf("tag-only: got %q want %q", got, string(want))
	}
}

func errorsEqual(a, b error) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Error() == b.Error() // sentinel errors are singletons
	}
}

func TestExtractPacketTooShort(t *testing.T) {
	mp := &BERPacket{
		data:   []byte{0x02, 0x01, 0x00}, // INTEGER 0
		offset: 2,                        // already 2 bytes in ⇒ only 1 left
	}
	sub, err := extractPacket(mp, 5) // ask for 5 bytes – impossible

	if sub.Type() != invalidEncodingRule {
		t.Errorf("expected nil sub-packet, got %#v", sub)
	}
	if err == nil || err.Error() != errorASN1Expect(5, 1, "Length").Error() {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFormatHexLongFormTruncated(t *testing.T) {
	// Tag 0x04 (OCTET STRING)
	// 0x82 declares *two* length octets but we supply only one (0x01).
	in := []byte{0x04, 0x02, 0x82, 0x01}
	want := "04 02 8201" // the function upper-cases and trims double spaces

	if got := formatHex(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestParseBodyLengthHeaderError(t *testing.T) {
	// INTEGER, long-form header but missing the 2 length octets
	b := []byte{0x02, 0x82}
	_, err := parseBody(b, 0, BER)

	if !errorsEqual(err, errorTruncatedLength) {
		t.Fatalf("expected errorTruncatedLength, got %v", err)
	}
}

func TestParseBodyIndefiniteOK(t *testing.T) {
	// SEQUENCE, indefinite
	//   INTEGER 1
	//   EOC
	stream := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}

	out, err := parseBody(stream, 0, BER)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []byte{0x02, 0x01, 0x01}
	if !bytes.Equal(out, want) {
		t.Errorf("content mismatch: got % X  want % X", out, want)
	}
}

func TestParseFullBytesLenSubZeroSlice(t *testing.T) {
	// Valid BOOLEAN FALSE
	pkt := []byte{0x01, 0x01, 0x00}
	// Pass off == len(pkt) so that sub := data[off:] becomes empty.
	got, err := parseFullBytes(pkt, len(pkt), BER)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Errorf("wanted full packet back, got % X", got)
	}
}

func TestParseFullBytesTagIdentifierError(t *testing.T) {
	_, err := parseFullBytes(nil, 0, BER) // empty ⇒ tag identifier error
	if !errorsEqual(err, errorEmptyIdentifier) {
		t.Fatalf("expected errorEmptyIdentifier, got %v", err)
	}
}

func TestParseFullBytesLengthHeaderError(t *testing.T) {
	// INTEGER with truncated long-form length
	b := []byte{0x02, 0x82}
	_, err := parseFullBytes(b, 0, BER)

	if !errorsEqual(err, errorTruncatedLength) {
		t.Fatalf("expected errorTruncatedLength, got %v", err)
	}
}

func TestParseFullBytesIndefiniteOK(t *testing.T) {
	stream := []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00}
	out, err := parseFullBytes(stream, 0, BER)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, stream) {
		t.Errorf("got % X want identical stream", out)
	}
}

func TestFindEOCOk(t *testing.T) {
	// [0]  Indefinite { [Primitive INTEGER 1] } EOC
	b := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	idx, err := findEOC(b[2:]) // hand inner slice to mimic nested parsing
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 3 { // INTEGER TLV is 3 bytes long
		t.Errorf("expected index 3 (right after INTEGER), got %d", idx)
	}
}

func TestFindEOCHeaderErrors(t *testing.T) {
	// 0x1F alone is an unterminated high-tag identifier
	if _, err := findEOC([]byte{0x1F}); !errorsEqual(err, errorTruncatedTag) {
		t.Fatalf("unterminated identifier: expected errorTruncatedTag, got %v", err)
	}

	// Valid identifier but *length* header is truncated: 0x02 0x82
	if _, err := findEOC([]byte{0x02, 0x82}); !errorsEqual(err, errorTruncatedLength) {
		t.Fatalf("truncated length: expected errorTruncatedLength, got %v", err)
	}
}

func TestFormatHexLongFormComplete(t *testing.T) {
	// 0x04 OCTET STRING
	// 0x82 → “two length bytes follow”
	// 0x00 0x01 → length = 1
	// 0xAA       → single content byte
	in := []byte{0x04, 0x82, 0x00, 0x01, 0xAA}

	want := "04 820001 AA"
	if got := formatHex(in); got != want {
		t.Fatalf("formatHex long-form: got %q want %q", got, want)
	}
}

func TestParseFullBytesIndefiniteWithOffset(t *testing.T) {
	// Build: XX XX | SEQUENCE ∞ { INTEGER 5 } EOC
	obj := []byte{
		0x30, 0x80, // SEQUENCE, indefinite
		0x02, 0x01, 0x05,
		0x00, 0x00, // EOC
	}
	full := append([]byte{0xAA, 0xBB}, obj...) // prepend padding
	out, err := parseFullBytes(full, 2, BER)   // offset 2 ⇒ points at obj
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, obj) {
		t.Errorf("returned slice mismatch: got % X  want % X", out, obj)
	}
}

func TestFindEOCDepthDecrement(t *testing.T) {
	// SEQ ∞ { SET ∞ { INTEGER 5 } EOC } EOC
	stream := []byte{
		0x30, 0x80, // outer SEQ, ∞
		0x31, 0x80, // inner SET, ∞
		0x02, 0x01, 0x05, // INTEGER 5
		0x00, 0x00, // ← inner EOC  (hits depth-- path)
		0x00, 0x00, // outer EOC
	}

	idx, err := findEOC(stream[2:]) // start *inside* outer body
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := 7
	if idx != want {
		t.Errorf("index mismatch: got %d want %d", idx, want)
	}
}

func ExamplePacket_sequenceWithGoStringAndInteger() {
	type MySequence struct {
		Name string `asn1:"printable"`
		Age  int    `asn1:"integer"`
	}

	opts := Options{}
	opts.SetClass(1) // encode sequence as APPLICATION class

	mine := MySequence{"Jesse", 48}

	pkt, err := Marshal(mine, With(DER, opts))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Encoded value: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded value: %s,%d", mine2.Name, mine2.Age)
	// Output:
	// Encoded value: 60 0A 13054A65737365020130
	// Decoded value: Jesse,48
}

func TestSequence_FieldsExplicit(t *testing.T) {
	type mySequence struct {
		Field0 string `asn1:"explicit,octet,tag:0"`
		Field1 string `asn1:"explicit,octet,tag:1,optional"`
		Field2 string `asn1:"explicit,octet,tag:2"`
	}

	mine := mySequence{"Hello", "World", "!!!"}

	hexes := map[EncodingRule]string{
		BER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
		CER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
		DER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [explicit, encoding]: %v", t.Name(), err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed [%s explicit encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}

		var mine2 mySequence
		if err = Unmarshal(pkt, &mine2); err != nil {
			t.Fatalf("%s failed [explicit, decoding]: %v", t.Name(), err)
		}
	}
}

func TestSequence_FieldsImplicit(t *testing.T) {
	type mySequence struct {
		Field0 string `asn1:"octet,tag:0"`
		Field1 string `asn1:"octet,tag:1,optional"`
		Field2 string `asn1:"octet,tag:2"`
	}

	mine := mySequence{"Hello", "World", "!!!"}

	hexes := map[EncodingRule]string{
		BER: `30 13 800548656C6C6F8105576F726C648203212121`,
		CER: `30 13 800548656C6C6F8105576F726C648203212121`,
		DER: `30 13 800548656C6C6F8105576F726C648203212121`,
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [implicit, encoding]: %v", t.Name(), err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed [%s implicit encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}

		var mine2 mySequence
		if err = Unmarshal(pkt, &mine2); err != nil {
			t.Fatalf("%s failed [implicit, decoding]: %v", t.Name(), err)
		}
	}
}

func TestSequence_PrimitiveFieldsExplicit(t *testing.T) {
	type mySequence struct {
		Field0 OctetString `asn1:"explicit,tag:0"`
		Field1 OctetString `asn1:"explicit,tag:1,optional"`
		Field2 OctetString `asn1:"explicit,tag:2"`
	}

	mine := mySequence{OctetString("Hello"), OctetString("World"), OctetString("!!!")}

	hexes := map[EncodingRule]string{
		BER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
		CER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
		DER: `30 19 A007040548656C6C6FA1070405576F726C64A2050403212121`,
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [explicit, encoding]: %v", t.Name(), err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed [%s explicit encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}

		var mine2 mySequence
		if err = Unmarshal(pkt, &mine2); err != nil {
			t.Fatalf("%s failed [explicit, decoding]: %v", t.Name(), err)
		}
	}
}

func TestSequence_PrimitiveFieldsImplicit(t *testing.T) {
	type mySequence struct {
		Field0 OctetString `asn1:"tag:0"`
		Field1 OctetString `asn1:"tag:1,optional"`
		Field2 OctetString `asn1:"tag:2"`
	}

	mine := mySequence{OctetString("Hello"), OctetString("World"), OctetString("!!!")}

	hexes := map[EncodingRule]string{
		BER: `30 13 800548656C6C6F8105576F726C648203212121`,
		CER: `30 13 800548656C6C6F8105576F726C648203212121`,
		DER: `30 13 800548656C6C6F8105576F726C648203212121`,
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(mine, With(rule))
		if err != nil {
			t.Fatalf("%s failed [implicit, encoding]: %v", t.Name(), err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed [%s implicit encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}

		var mine2 mySequence
		if err = Unmarshal(pkt, &mine2); err != nil {
			t.Fatalf("%s failed [implicit, decoding]: %v", t.Name(), err)
		}
	}
}

func BenchmarkEncodeDirectoryString(b *testing.B) {
	dir := Choice{Value: PrintableString("Hello")}
	for n := 0; n < b.N; n++ {
		_, _ = Marshal(dir)
	}
}

func BenchmarkDecodeDirectoryString(b *testing.B) {
	pkt, _ := Marshal(Choice{Value: PrintableString("Hello")})
	var out Choice
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = Unmarshal(pkt, &out)
	}
}

var testPktPool = sync.Pool{New: func() any { return &testPacket{} }}

func getTestPacket() *testPacket { return testPktPool.Get().(*testPacket) }
func putTestPacket(p *testPacket) {
	*p = testPacket{}
	testPktPool.Put(p)
}
