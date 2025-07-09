package asn1plus

import (
	"fmt"
	"reflect"
	"testing"
)

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
	unmarshalSequence(reflect.ValueOf(struct{}{}), &BERPacket{}, nil)

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
