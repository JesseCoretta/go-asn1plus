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
			boo = strInSlice(a, b)
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
		OctetString
		PrintableString
	}

	mine := mySequence{
		OctetString(`Hello world`),
		PrintableString(`Hello world`),
	}

	pkt := BER.New()

	unmarshalSet(reflect.ValueOf(&mine), pkt, nil)
}
