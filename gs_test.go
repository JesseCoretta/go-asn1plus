package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleGraphicString() {
	vs, err := NewGraphicString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vs)
	// Output: Jesse
}

func ExampleGraphicString_dER() {
	// Parse string into a GraphicString instance
	vs, err := NewGraphicString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode GraphicString into Packet instance
	var der Packet
	if der, err = Marshal(vs); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new GraphicString instance
	var vs2 GraphicString
	if err = Unmarshal(der, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", vs, vs.String() == vs2.String(), vs2)
	// Output: asn1plus.GraphicString values match: true (Jesse)
}

func TestGraphicString_codecov(_ *testing.T) {
	var od GraphicString
	od.Tag()
	od.Len()
	od.IsPrimitive()
	_ = od.String()

	_, _ = NewGraphicString(nil)
	_, _ = NewGraphicString(string(rune(2)))
	_, _ = NewGraphicString(struct{}{})
	od.read(nil, TLV{}, &Options{})
	scanGeneralStringChars(string(rune(0)))
}

func TestGraphicString_encodingRules(t *testing.T) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		GraphicString("objectName"),
	} {
		for _, rule := range encodingRules {
			od, err := NewGraphicString(value)
			if err != nil {
				t.Fatalf("%s failed [New GraphicString]: %v", t.Name(), err)
			}
			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our GraphicString instance
			var pkt Packet
			if pkt, err = Marshal(od, WithEncoding(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our Packet into a new GraphicString instance
			var other GraphicString
			if err = Unmarshal(pkt, &other); err != nil {
				t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			}

			// Compare string representations
			if od.String() != other.String() {
				t.Fatalf("%s failed [%s :: %T string cmp.]:\n\twant: '%s'\n\tgot:  '%s'",
					t.Name(), rule, od, od, other)
			}
		}
	}
}

func ExampleGraphicString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o GraphicString) GraphicString { return o },
		func(o GraphicString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o GraphicString) GraphicString { return o },
		func(o GraphicString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewGraphicString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewGraphicString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}
