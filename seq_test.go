package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleRawContent() {
	type MySequence struct {
		RawContent        // must be first field
		A          string `asn1:"octet"`
		B          int
	}

	// Here we manufacture a PDU by hand
	// just for brevity.
	rawContent := []byte{
		0x04, 0x01, 'X',
		0x02, 0x01, 0x05,
	}
	rawSeq := append([]byte{0x30, byte(len(rawContent))}, rawContent...)
	pkt := BER.New(rawSeq...)
	pkt.SetOffset()

	// Decode pkt into MySequence
	var my MySequence
	if err := Unmarshal(pkt, &my); err != nil {
		fmt.Printf("Unmarshal failed: %v", err)
		return
	}

	fmt.Printf("%#v\n", my.RawContent)
	// Output: asn1plus.RawContent{0x4, 0x1, 0x58, 0x2, 0x1, 0x5}
}

func TestSequence_Extensions_RoundTrip(t *testing.T) {
	raw := []byte{
		0x30, 0x0A,
		0x0C, 0x05, 'H', 'e', 'l', 'l', 'o',
		0x02, 0x01, 0x7B,
	}

	pkt := BER.New(raw...)
	pkt.SetOffset()

	//t.Logf("%#v\n", pkt)

	var seq struct {
		Name       string `asn1:"utf8"`
		Extensions []TLV  `asn1:"..."`
	}

	if err := Unmarshal(pkt, &seq); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if seq.Name != "Hello" {
		t.Errorf("Name = %q; want %q", seq.Name, "Hello")
	}

	if got := len(seq.Extensions); got != 1 {
		t.Fatalf("Extensions length = %d; want 1", got)
	}
	ext := seq.Extensions[0]

	if ext.Tag != 2 {
		t.Errorf("Extensions[0].Tag = %d; want 2", ext.Tag)
	}

	if !btseq(ext.Value, []byte{0x7B}) {
		t.Errorf("Extensions[0].Value = % X; want 7B", ext.Value)
	}

	outPkt, err := Marshal(seq)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !btseq(outPkt.Data(), raw) {
		t.Errorf("Round-trip bytes = % X; want % X", outPkt.Data(), raw)
	}
}

func TestSequence_ComponentsOf(t *testing.T) {
	type ComponentSequence struct {
		Name UTF8String `asn1:"tag:1"`
		Min  Integer    `asn1:"tag:2"`
		Max  Integer    `asn1:"tag:3"`
	}

	type MySequence struct {
		Field1            PrintableString `asn1:"tag:0"`
		ComponentSequence `asn1:"components-of"`
		Field3            OctetString `asn1:"tag:4"`
	}

	ten, _ := NewInteger(10)
	seventeen, _ := NewInteger(17)
	j := UTF8String("Jesse")
	oct := OctetString("octets")
	ps := PrintableString("testing")

	my := MySequence{
		Field1: ps,
		ComponentSequence: ComponentSequence{
			Name: j,
			Min:  ten,
			Max:  seventeen,
		},
		Field3: oct,
	}

	pkt, err := Marshal(my)
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var my2 MySequence
	if err = Unmarshal(pkt, &my2); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	nten := my2.ComponentSequence.Min
	if nten.Ne(ten) {
		t.Fatalf("%s failed [struct cmp.]:\n\twant: %s\n\tgot:  %s", t.Name(), ten, nten)
	}
}

func TestSequence_IntFields(t *testing.T) {
	type MySequence struct {
		Field0 Integer
		Field1 Integer
		Field2 Integer
		Field3 Integer
	}
	zero, _ := NewInteger(0)
	one, _ := NewInteger(1)
	two, _ := NewInteger(2)
	three, _ := NewInteger(3)

	my := MySequence{zero, one, two, three}

	pkt, err := Marshal(my)
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var my2 MySequence
	if err = Unmarshal(pkt, &my2); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
}

func TestSequenceOf_roundTrip(t *testing.T) {
	type partialAttribute struct {
		Type OctetString
		Vals []OctetString
	}

	type modifyRequestChange struct {
		Operation    Enumerated
		Modification partialAttribute
	}

	mrc := []modifyRequestChange{
		{
			Operation: 0,
			Modification: partialAttribute{
				Type: OctetString("objectClass"),
				Vals: []OctetString{
					OctetString("account"),
				},
			},
		},
		{
			Operation: 2,
			Modification: partialAttribute{
				Type: OctetString("cn"),
				Vals: []OctetString{
					OctetString("xyz"),
				},
			},
		},
	}

	opts := &Options{Sequence: true}
	pkt, err := Marshal(mrc, With(opts))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var mrc2 []modifyRequestChange
	if err = Unmarshal(pkt, &mrc2, With(opts)); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	//t.Logf("%#v\n", mrc2)
}

func TestMarshal_SequenceEncodingRulesWith(t *testing.T) {
	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
	}

	my := MySequence{
		OctetString("Hello0"),
		PrintableString("Hello1"),
	}

	opts := Options{}
	opts.SetTag(TagSequence)
	opts.SetClass(ClassApplication)

	for _, rule := range encodingRules {
		pkt, err := Marshal(my,
			With(rule, opts))

		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var my2 MySequence
		if err = Unmarshal(pkt, &my2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
	}
}

func TestMarshal_SequenceEncodingRules(t *testing.T) {
	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
	}

	my := MySequence{
		OctetString("Hello0"),
		PrintableString("Hello1"),
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(my, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var my2 MySequence
		if err = Unmarshal(pkt, &my2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
	}
}

func TestMarshal_SequenceNested(t *testing.T) {
	type OtherSequence struct {
		Field1 UTF8String
	}

	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString
		Sub    OtherSequence
		//Ptr    *OtherSequence `asn1:"optional"`
	}

	my := MySequence{
		Field1: OctetString("Hello0"),
		Field2: PrintableString("Hello1"),
		Sub: OtherSequence{
			Field1: UTF8String("Hello2"),
		},
		//Ptr: &OtherSequence{
		//	Field1: UTF8String("Hello3"),
		//},
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(my, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var my2 MySequence
		if err = Unmarshal(pkt, &my2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
	}
}

func TestSequence_codecov(_ *testing.T) {
	unmarshalSequence(refValueOf(struct{}{}), &BERPacket{}, nil)

	type badSequence struct {
		PrintableString `asn1:"AUTOMATIC,EXPLICIT"`
	}
	marshalSequence(refValueOf(badSequence{PrintableString("Yo")}), &BERPacket{}, &Options{Automatic: true, Explicit: true})

	type choiceSequence struct {
		PrintableString `asn1:"AUTOMATIC,EXPLICIT"`
		Choice          `asn1:"EXPLICIT,choices:missingChoices"`
	}

	checkSequenceFieldCriticality("bogus", refValueOf(nil), false)

	//marshalSequenceChoiceFieldPrimitive(&Options{}, Choice{Value: OctetString(`theChosenOne`)}, &BERPacket{})
	//marshalSequenceChoiceFieldPrimitive(&Options{}, Choice{Value: `theChosenOne`}, &BERPacket{})

	dat := []byte{
		0x30, 0x1a, 0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c,
		0x6f, 0x30, 0x13, 0x06, 0x48, 0x65, 0x6c, 0x6c,
		0x6f, 0x31, 0x30, 0x08, 0x0c, 0x06, 0x48, 0x65,
		0x6c, 0x6c, 0x6f, 0x32,
	}

	unmarshalSequence(refValueOf(struct{}{}), &BERPacket{offset: 100, data: []byte{0x30, 0x1, 0x5}}, nil)
	unmarshalSequence(refValueOf(struct{}{}), &BERPacket{offset: 21, data: dat}, nil)
	type privateFields struct {
		private OctetString
	}
	Unmarshal(&BERPacket{data: []byte{0x30, 0x1, 0x5}}, &privateFields{})
	type bogusFieldTag struct {
		PrintableString `asn1:"AUTOMATIC,EXPLICIT"`
	}
	Unmarshal(&BERPacket{data: []byte{0x30, 0x1, 0x5}}, &bogusFieldTag{})
}

func ExamplePDU_automaticTaggingBER() {
	type MySequence struct {
		A Integer         `asn1:"tag:0"`
		B PrintableString `asn1:"tag:1"`
	}

	nint, _ := NewInteger(42) // safe to shadow error if non-string
	ps := PrintableString("Hi")
	mine := MySequence{A: nint, B: ps}
	opts := Options{Automatic: true}

	pkt, err := Marshal(mine, With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("BER packet hex: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	// Output: BER packet hex: 30 07 80012A81024869
}

func TestSequence_AutomaticTagging(t *testing.T) {
	type MySequence struct {
		A Integer         `asn1:"tag:0"`
		B PrintableString `asn1:"tag:1"`
	}

	nint, _ := NewInteger(42) // safe to shadow error if non-string
	ps := PrintableString("Hi")
	in := MySequence{A: nint, B: ps}
	opts := Options{Automatic: true}

	// 30            -- SEQUENCE
	// 07            -- length
	// 80 01 2A      -- [0] IMPLICIT INTEGER 42
	// 81 02 48 69   -- [1] IMPLICIT PrintableString "Hi"
	hexes := map[EncodingRule]string{
		BER: "30 07 80012A81024869",
		CER: "30 07 80012A81024869",
		DER: "30 07 80012A81024869",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(in, With(rule, opts))

		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v'", t.Name(), rule, err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed: unexpected %s encoding:\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var out MySequence
		if err = Unmarshal(pkt, &out, With(opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v'", t.Name(), rule, err)
		}

		if out != in {
			t.Fatalf("%s failed: %s round-trip mismatch: got %+v want %+v",
				t.Name(), rule, out, in)
		}
	}
}
