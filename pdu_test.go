package asn1plus

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
)

/*
testPacket implements an invalid-ish PDU qualifier used
solely for tripping special corner-cases in unit tests.
*/
type testPacket struct {
	data   []byte
	indef  bool
	offset int
	length int          // reported Len(); can differ from len(data)
	typ    EncodingRule // hardwire a type
}

func (r testPacket) Data() []byte                          { return r.data }
func (r testPacket) Offset() int                           { return r.offset }
func (r *testPacket) SetOffset(i ...int)                   { setPacketOffset(r, i...) }
func (r *testPacket) AddOffset(i int)                      { incPacketOffset(r, i) }
func (r testPacket) Len() int                              { return r.length }
func (r testPacket) Type() EncodingRule                    { return r.typ }
func (r testPacket) Hex() string                           { return formatHex(r) }
func (r testPacket) Dump(w io.Writer, wrapAt ...int) error { return nil }
func (r *testPacket) HasMoreData() bool                    { return r.offset < len(r.data) }
func (r *testPacket) TLV() (TLV, error)                    { return getTLV(r, nil) }
func (r *testPacket) ID() string                           { return `` }
func (r *testPacket) WriteTLV(tlv TLV) error               { return writeTLV(r, tlv, nil) }
func (r *testPacket) allowsIndefinite() bool               { return r.indef }

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
	need := r.Len() + len(data)

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
This example demonstrates the manual creation of a [PDU] instance using
pre-encoded bytes as input.
*/
func ExamplePDU_manualCreation() {
	// For the purposes of this example, we chose BER to
	// encode a UTF-8 string.
	berBytes := []byte{
		0x0c, 0x16, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
		0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
	}

	pkt := BER.New(berBytes...)
	var u8 UTF8String

	if err := Unmarshal(pkt, &u8); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(u8)
	// Output: this is a UTF-8 string
}

func ExamplePDU_Dump_primitive() {
	var oct OctetString = OctetString("Testing 123")
	pkt, err := Marshal(oct)
	if err != nil {
		fmt.Println(err)
		return
	}

	var w bytes.Buffer
	if err = pkt.Dump(&w); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", w.String())
	// Output:
	// 04 0B    # OCTET STRING, len=11
	//   54 65 73 74 69 6E 67 20 31 32 33
}

func ExamplePDU_Dump_set() {
	var set []OctetString = []OctetString{
		OctetString("Testing 123"),
		OctetString("Testing 456"),
		OctetString("Testing 789"),
		OctetString("Testing AEF620044300EC123AAA54FFFF24542511010"),
	}

	pkt, err := Marshal(set)
	if err != nil {
		fmt.Println(err)
		return
	}

	var w bytes.Buffer
	if err = pkt.Dump(&w); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", w.String())
	// Output:
	// 11 56    # SET, len=86
	//   04 0B    # OCTET STRING, len=11
	//     54 65 73 74 69 6E 67 20 31 32 33
	//   04 0B    # OCTET STRING, len=11
	//     54 65 73 74 69 6E 67 20 34 35 36
	//   04 0B    # OCTET STRING, len=11
	//     54 65 73 74 69 6E 67 20 37 38 39
	//   04 2D    # OCTET STRING, len=45
	//     54 65 73 74 69 6E 67 20 41 45 46 36 32 30 30 34 34 33 30 30 45 43 31 32
	//     33 41 41 41 35 34 46 46 46 46 32 34 35 34 32 35 31 31 30 31 30
}

func ExamplePDU_Dump_sequence() {

	// Here, we implement the following ASN.1 structure ...

	/*
		DeepSequence := [CONTEXT SPECIFIC 2] EXPLICIT SEQUENCE {
			field2 OCTET STRING
		}

		SubSequence ::= [APPLICATION 0] EXPLICIT SEQUENCE {
		    values   SET OF OCTET STRING,
		    deep     DeepSequence
		}

		MySequence ::= [APPLICATION 7] IMPLICIT SEQUENCE {
		    field0   PrintableString,
		    field1   OCTET STRING        OPTIONAL,
		    field2   SubSequence
		}
	*/

	// ... using Go structs and ASN.1 primitives:
	type DeepSequence struct {
		Field2 OctetString
	}

	type SubSequence struct {
		Values []OctetString
		Deep   DeepSequence `asn1:"tag:2"` // [CONTEXT SPECIFIC 2]
	}

	type MySequence struct {
		Field0 PrintableString
		Field1 OctetString `asn1:"optional"`
		Field2 SubSequence `asn1:"application,tag:0"` // [APPLICATION 0]
	}

	// Now we populate with actual content ...
	my := MySequence{
		Field0: PrintableString("Print me"),
		Field2: SubSequence{
			Values: []OctetString{
				OctetString("Zero"),
				OctetString("One"),
				OctetString("Two"),
				OctetString("Three"),
			},
			Deep: DeepSequence{
				Field2: OctetString("Deep value"),
			},
		},
	}

	// Prepare options for class/tag assignment to
	// the top-level MySequence struct.
	opts := Options{}

	// SetClass(1) + SetTag(7) == [APPLICATION 7]
	opts.SetClass(1)
	opts.SetTag(7)

	// BER encode MySequence
	pkt, err := Marshal(my, With(BER, opts))
	if err != nil {
		fmt.Println(err)
		return
	}

	var w bytes.Buffer // implements io.Writer

	// Optionally, users may pass a variadic integer to
	// better control line-wrapping for particularly
	// large values.
	if err = pkt.Dump(&w); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", w.String())
	// Output:
	// 07 35    # [APPLICATION 7], len=53
	//   13 08    # PrintableString, len=8
	//     50 72 69 6E 74 20 6D 65
	//   04 00    # OCTET STRING, len=0
	//   00 27    # [APPLICATION 0], len=39
	//     11 17    # SET, len=23
	//       04 04    # OCTET STRING, len=4
	//         5A 65 72 6F
	//       04 03    # OCTET STRING, len=3
	//         4F 6E 65
	//       04 03    # OCTET STRING, len=3
	//         54 77 6F
	//       04 05    # OCTET STRING, len=5
	//         54 68 72 65 65
	//     02 0C    # [CONTEXT SPECIFIC 2], len=12
	//       04 0A    # OCTET STRING, len=10
	//         44 65 65 70 20 76 61 6C 75 65
}

func TestPDU_invalidPacket(_ *testing.T) {
	var invp invalidPacket
	invp.Type()
	invp.Data()
	invp.Offset()
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

func TestPDU_PeekTLV(t *testing.T) {
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

func TestPDU_RawValueCompatSequence(t *testing.T) {
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

func TestPDU_codecov(_ *testing.T) {
	findEOC([]byte{0x14, 0x33})
	formatHex([]byte{})
	pktB := &BERPacket{}
	pktB.Type().OID()
	pktD := &BERPacket{}
	pktD.Type().OID()
	With(&Options{})
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

	marshalValue(refValueOf(nil), &BERPacket{}, nil)
	var nill *struct{}
	marshalValue(refValueOf(nill), &BERPacket{}, nil)
	marshalValue(refValueOf(OctetString("test")), &BERPacket{}, nil)

	unmarshalHandleTag("octet", &BERPacket{}, &TLV{Tag: 4, Length: 4000}, &opts)
	berBytes := []byte{
		0x0c, 0x16, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
		0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
	}

	o := OctetString("test")
	unmarshalPrimitive(&BERPacket{data: berBytes}, refValueOf(&o), &opts)

	BER.Extends(CER)

	rc := new(realCodec[Real])
	marshalPrimitive(refValueOf(rc), &BERPacket{}, nil)
	marshalPrimitive(refValueOf(rc), &BERPacket{}, &Options{Explicit: true})
	unmarshalPrimitive(&BERPacket{data: berBytes}, refValueOf(rc), &Options{Explicit: true})
	unmarshalPrimitive(&BERPacket{data: berBytes}, refValueOf("test"), &Options{Explicit: true})
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

func ExamplePDU_sequence() {
	type MySequence struct {
		Name PrintableString
		Age  Integer
	}

	opts := Options{}
	opts.SetClass(1) // encode sequence as APPLICATION class

	nint, _ := NewInteger(48)

	mine := MySequence{PrintableString("Jesse"), nint}

	pkt, err := Marshal(mine, With(BER, opts))
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

	fmt.Printf("Decoded value: %s,%s", mine2.Name, mine2.Age)
	// Output:
	// Encoded value: 60 0A 13054A65737365020130
	// Decoded value: Jesse,48
}

func TestSequence_FieldsExplicit(t *testing.T) {
	type mySequence struct {
		Field0 OctetString `asn1:"explicit,tag:0"`
		Field1 OctetString `asn1:"explicit,tag:1,optional"`
		Field2 OctetString `asn1:"explicit,tag:2"`
	}

	mine := mySequence{OctetString("Hello"),
		OctetString("World"), OctetString("!!!")}

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
		Field0 OctetString `asn1:"tag:0"`
		Field1 OctetString `asn1:"tag:1,optional"`
		Field2 OctetString `asn1:"tag:2"`
	}

	mine := mySequence{OctetString("Hello"),
		OctetString("World"), OctetString("!!!")}

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

func TestConstructorMap_ShouldPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	panicOnMissingEncodingRuleConstructor(map[EncodingRule]func(...byte) PDU{})
}

/*
func BenchmarkEncodeDirectoryString(b *testing.B) {
	dir := NewChoice(PrintableString("Hello"))
	for n := 0; n < b.N; n++ {
		_, _ = Marshal(dir)
	}
}

func BenchmarkDecodeDirectoryString(b *testing.B) {
	pkt, _ := Marshal(NewChoice(PrintableString("Hello")))
	var out Choice
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = Unmarshal(pkt, &out)
	}
}
*/

var testPktPool = sync.Pool{New: func() any { return &testPacket{} }}

func getTestPacket() *testPacket { return testPktPool.Get().(*testPacket) }
func putTestPacket(p *testPacket) {
	*p = testPacket{}
	testPktPool.Put(p)
}

func BenchmarkPDU_SequenceBER(b *testing.B) {
	type MySequence struct {
		Name string `asn1:"printable"`
		Age  int    `asn1:"integer"`
		Raw  OctetString
	}

	mine := MySequence{
		Name: "Bill Smith",
		Age:  80,
		Raw:  OctetString(`fjkewjlkjlkwjlkr324j589234torhj23trioh324t8294ht24ih243hui4h4hih3i`),
	}

	for i := 0; i < b.N; i++ {
		pkt, err := Marshal(mine, With(BER))
		if err != nil {
			b.Fatal(err)
		}

		var mine2 MySequence
		if err = Unmarshal(pkt, &mine2); err != nil {
			b.Fatal(err)
		}
	}
}
