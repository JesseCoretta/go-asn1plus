package asn1plus

import (
	"fmt"
	"testing"
)

func TestSet_Extensions(t *testing.T) {
	type MySET struct {
		Name       string `asn1:"utf8"`
		Extensions []TLV  `asn1:"..."`
	}

	// A BER‐encoded SET containing:
	//   • UTF8String "Hello"  → 0x0C 0x05 48 65 6C 6C 6F
	//   • INTEGER 123         → 0x02 0x01 7B
	raw := []byte{
		0x31, 0x0A, // SET, length=10
		0x0C, 0x05, 'H', 'e', 'l', 'l', 'o', // UTF8String "Hello"
		0x02, 0x01, 0x7B, // INTEGER 123
	}

	pkt := BER.New(raw...)
	pkt.SetOffset()

	var s MySET
	if err := Unmarshal(pkt, &s); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got, want := s.Name, "Hello"; got != want {
		t.Errorf("Name = %q; want %q", got, want)
	}

	if n := len(s.Extensions); n != 1 {
		t.Fatalf("Extensions length = %d; want 1", n)
	}
	ext := s.Extensions[0]

	if ext.Tag != 2 {
		t.Errorf("Extensions[0].Tag = %d; want 2", ext.Tag)
	}
	if !btseq(ext.Value, []byte{0x7B}) {
		t.Errorf("Extensions[0].Value = % X; want 7B", ext.Value)
	}

	outPkt, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !btseq(outPkt.Data(), raw) {
		t.Errorf("Round-trip = % X; want % X", outPkt.Data(), raw)
	}
}

func ExampleOctetString_setOf() {
	values := []OctetString{
		OctetString(`Zero`),
		OctetString(`One`),
		OctetString(`Two`),
		OctetString(`Three`),
		OctetString(`Four`),
		OctetString(`Five`),
	}

	pkt, err := Marshal(values, With(BER))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("BER encoding: %s\n", pkt.Hex())

	var values2 []OctetString
	if err = Unmarshal(pkt, &values2); err != nil {
		fmt.Println(err)
		return
	}

	for i := 0; i < len(values2); i++ {
		fmt.Printf("Slice %d: %s (%T)\n", i, values2[i], values2[i])
	}

	// Output:
	// BER encoding: 31 23 04045A65726F04034F6E65040354776F040554687265650404466F7572040446697665
	// Slice 0: Zero (asn1plus.OctetString)
	// Slice 1: One (asn1plus.OctetString)
	// Slice 2: Two (asn1plus.OctetString)
	// Slice 3: Three (asn1plus.OctetString)
	// Slice 4: Four (asn1plus.OctetString)
	// Slice 5: Five (asn1plus.OctetString)
}

func ExampleOctetString_sequenceWithSet() {
	type substringAssertion struct {
		Initial OctetString   `asn1:"tag:0"`
		Any     []OctetString `asn1:"tag:1"`
		Final   OctetString   `asn1:"tag:2"`
	}

	// subs*r*ngs*are cool
	ssa := substringAssertion{
		Initial: OctetString(`subs`),
		Any: []OctetString{
			OctetString(`r`),
			OctetString(`ngs`),
		},
		Final: OctetString(`are cool`),
	}

	pkt, err := Marshal(ssa, With(BER))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("BER encoding: %s\n", pkt.Hex())

	var dest substringAssertion
	if err = Unmarshal(pkt, &dest); err != nil {
		fmt.Println(err)
		return
	}

	// Output:
	// BER encoding: 30 1A 800473756273A10804017204036E6773820861726520636F6F6C
}

func TestSet_encodingRules(t *testing.T) {
	equalSlices := func(a, b []string, rule EncodingRule) (boo bool) {
		switch rule {
		case DER:
			// If DER canonical encoding, then we can
			// order the values lexographically.
			if len(a) == len(b) {
				boo = true
				for i := 0; i < len(a); i++ {
					if a[i] != b[i] {
						boo = false
					}
				}
			}
		default:
			for i := 0; i < len(a) && !boo; i++ {
				for j := 0; j < len(b) && !boo; j++ {
					boo = a[i] == b[j]
				}
			}
		}

		return boo
	}

	type mySET struct {
		Items []Integer
	}

	// Create some Integer values.
	int1, _ := NewInteger(7)
	int2, _ := NewInteger(3)
	int3, _ := NewInteger(5)

	// Create a mySet instance with values in unsorted order.
	orig := mySET{
		Items: []Integer{int1, int2, int3},
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(orig, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		//t.Logf("%s encoding: %s\n", rule, pkt.Hex())

		var decoded mySET
		if err = Unmarshal(pkt, &decoded); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}

		got := make([]string, len(decoded.Items))
		for i, v := range decoded.Items {
			got[i] = v.String()
		}

		expected := []string{"3", "5", "7"}
		if !equalSlices(got, expected, rule) {
			t.Fatalf("%s failed [%s SET cmp.]:\n\twant: %v\n\tgot  %v",
				t.Name(), rule, expected, got)
		}
	}
}

func TestSet_codecov(_ *testing.T) {
	isSet(struct{}{}, nil)
	isSet([]string{}, nil)

	opts := &Options{}
	opts.SetTag(14)
	isSet([]string{}, opts)
	isSet([]uint8{}, nil)

	type mySequence struct {
		Oct     OctetString
		PS      PrintableString
		private string
	}

	mine := mySequence{
		Oct: OctetString(`Hello world`),
		PS:  PrintableString(`Hello world`),
	}
	_ = marshalSet(refValueOf(struct{}{}), nil, nil)
	_ = marshalSet(refValueOf(rune(66)), nil, nil)

	type incompatibleSequence struct {
		Byte byte
	}
	incomp := incompatibleSequence{0x0F}

	_ = unmarshalSet(refValueOf(incomp), &BERPacket{data: []byte{0xa, 0x13, 0x07, 0x7e}}, nil)
	_ = unmarshalSet(refValueOf(mine), &BERPacket{data: []byte{0xa, 0x13, 0x07, 0x7e}}, nil)
	_ = unmarshalSet(refValueOf(struct{}{}), nil, nil)
	_ = unmarshalSet(refValueOf(rune(66)), nil, nil)

	pkt := BER.New()

	unmarshalSet(refValueOf(&mine), pkt, nil)
}
