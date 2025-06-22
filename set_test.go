package asn1plus

import (
	"reflect"
	"testing"
)

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
				t.Name(), rule, got, expected)
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
	_ = marshalSet(refValueOf(struct{}{}), nil, nil, 0)
	_ = marshalSet(refValueOf(rune(66)), nil, nil, 0)

	type incompatibleSequence struct {
		Byte byte
	}
	incomp := incompatibleSequence{0x0F}

	_ = unmarshalSet(refValueOf(incomp), &BERPacket{data: []byte{0xa, 0x13, 0x07, 0x7e}}, nil)
	_ = unmarshalSet(refValueOf(mine), &BERPacket{data: []byte{0xa, 0x13, 0x07, 0x7e}}, nil)
	_ = unmarshalSet(refValueOf(struct{}{}), nil, nil)
	_ = unmarshalSet(refValueOf(rune(66)), nil, nil)

	pkt := BER.New()

	unmarshalSet(reflect.ValueOf(&mine), pkt, nil)
}
