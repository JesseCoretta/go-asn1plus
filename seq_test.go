package asn1plus

import (
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

	for _, rule := range encodingRules {
		pkt, err := Marshal(my,
			WithEncoding(rule),
			WithOptions(Options{
				Class: ClassApplication,
				Tag:   TagSequence,
			}))

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
