package asn1plus

import (
	"fmt"
	"reflect"
	"testing"
)

func TestMarshal_SequenceEncodingRulesWithOptions(t *testing.T) {
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
			WithEncoding(rule),
			WithOptions(opts))

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
		pkt, err := Marshal(my, WithEncoding(rule))
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
		pkt, err := Marshal(my, WithEncoding(rule))
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
	unmarshalSequence(reflect.ValueOf(struct{}{}), &BERPacket{}, []Options{}...)
}

func ExamplePacket_automaticTaggingBER() {
	type MySequence struct {
		A int    `asn1:"integer"`
		B string `asn1:"printable"`
	}

	mine := MySequence{A: 42, B: "Hi"}
	opts := Options{Automatic: true}

	pkt, err := Marshal(mine,
		WithEncoding(BER),
		WithOptions(opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("BER packet hex: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2, WithOptions(opts)); err != nil {
		fmt.Println(err)
		return
	}

	// Output: BER packet hex: 30 07 80012A81024869
}

func TestSequence_AutomaticTagging(t *testing.T) {
	type MySequence struct {
		A int    `asn1:"integer"`
		B string `asn1:"printable"`
	}

	in := MySequence{A: 42, B: "Hi"}
	opts := Options{Automatic: true}

	// 30            -- SEQUENCE
	// 07            -- length
	// 80 01 2A      -- [0] IMPLICIT INTEGER 42
	// 81 02 48 69   -- [1] IMPLICIT PrintableString "Hi"
	hexes := map[EncodingRule]string{
		BER: "30 07 80012A81024869",
		DER: "30 07 80012A81024869",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(in,
			WithEncoding(rule),
			WithOptions(opts))

		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v'", t.Name(), rule, err)
		}

		got := pkt.Hex()
		if want := hexes[rule]; want != got {
			t.Fatalf("%s failed: unexpected %s encoding:\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var out MySequence
		if err = Unmarshal(pkt, &out, WithOptions(opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v'", t.Name(), rule, err)
		}

		if out != in {
			t.Fatalf("%s failed: %s round-trip mismatch: got %+v want %+v",
				t.Name(), rule, out, in)
		}
	}
}
