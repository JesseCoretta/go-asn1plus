package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleVisibleString() {
	vs, err := NewVisibleString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vs)
	// Output: Jesse
}

func ExampleVisibleString_bER() {
	// Parse string into a VisibleString instance
	vs, err := NewVisibleString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode VisibleString into Packet instance
	var pkt Packet
	if pkt, err = Marshal(vs, With(BER)); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new VisibleString instance
	var vs2 VisibleString
	if err = Unmarshal(pkt, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)\n", vs, vs.String() == vs2.String(), vs2)
	fmt.Printf("%T Hex: %s", pkt, pkt.Hex())
	// Output: asn1plus.VisibleString values match: true (Jesse)
	// *asn1plus.BERPacket Hex: 1A 05 4A65737365
}

func ExampleVisibleString_dER() {
	// Parse string into a VisibleString instance
	vs, err := NewVisibleString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode VisibleString into Packet instance
	var pkt Packet
	if pkt, err = Marshal(vs, With(DER)); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new VisibleString instance
	var vs2 VisibleString
	if err = Unmarshal(pkt, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)\n", vs, vs.String() == vs2.String(), vs2)
	fmt.Printf("%T Hex: %s", pkt, pkt.Hex())
	// Output: asn1plus.VisibleString values match: true (Jesse)
	// *asn1plus.DERPacket Hex: 1A 05 4A65737365
}

func TestVisibleString_codecov(t *testing.T) {
	for idx, value := range []any{
		`visibleString`,
		[]byte(`visibleString`),
		VisibleString(`visibleString`),
	} {
		for _, rule := range encodingRules {
			vs, err := NewVisibleString(value)
			if err != nil {
				t.Fatalf("%s[%d] failed [%s NewVisibleString]: %v",
					t.Name(), idx, rule, err)
			}

			vs.Tag()
			vs.IsZero()
			vs.IsPrimitive()
			_ = vs.String()

			var pkt Packet
			if pkt, err = Marshal(vs, With(rule)); err != nil {
				t.Fatalf("%s[%d] failed [%s encoding]: %v",
					t.Name(), idx, rule, err)
			}

			var vs2 VisibleString
			if err = Unmarshal(pkt, &vs2); err != nil {
				t.Fatalf("%s[%d] failed [%s decoding]: %v",
					t.Name(), idx, rule, err)
			}

			want := vs.String()
			if got := vs2.String(); want != got {
				t.Fatalf("%s[%d] failed [%s %T string cmp.]:\n\twant: '%s'\n\tgot:  '%s'",
					t.Name(), idx, rule, vs, want, got)
			}
		}
	}
	NewVisibleString([]byte{0x7F, 0x7F, 0x08})
	_, _ = NewVisibleString(struct{}{})
}
