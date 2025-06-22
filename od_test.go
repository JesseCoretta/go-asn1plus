package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleObjectDescriptor() {
	vs, err := NewObjectDescriptor("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vs)
	// Output: Jesse
}

func ExampleObjectDescriptor_dER() {
	// Parse string into a ObjectDescriptor instance
	vs, err := NewObjectDescriptor("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode ObjectDescriptor into Packet instance
	var der Packet
	if der, err = Marshal(vs); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new ObjectDescriptor instance
	var vs2 ObjectDescriptor
	if err = Unmarshal(der, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", vs, vs.String() == vs2.String(), vs2)
	// Output: asn1plus.ObjectDescriptor values match: true (Jesse)
}

func TestObjectDescriptor_codecov(_ *testing.T) {
	var od ObjectDescriptor
	od.Tag()
	od.Len()
	od.IsPrimitive()
	_ = od.String()

	_, _ = NewObjectDescriptor(nil)
	_, _ = NewObjectDescriptor(string(rune(2)))
	_, _ = NewObjectDescriptor(struct{}{})
}

func TestObjectDescriptor_encodingRules(t *testing.T) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		ObjectDescriptor("objectName"),
	} {
		for _, rule := range encodingRules {
			// Parse our ASN.1 OBJECT DESCRIPTOR
			od, err := NewObjectDescriptor(value)
			if err != nil {
				t.Fatalf("%s failed [New ObjectDescriptor]: %v", t.Name(), err)
			}
			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our ObjectDescriptor instance
			var pkt Packet
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			t.Logf("%T.%s :: %s\n", od, rule, pkt.Hex())

			// Decode our Packet into a new ObjectDescriptor instance
			var other ObjectDescriptor
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

func ExampleObjectDescriptor_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o ObjectDescriptor) ObjectDescriptor { return o },
		func(o ObjectDescriptor) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o ObjectDescriptor) ObjectDescriptor { return o },
		func(o ObjectDescriptor) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewObjectDescriptor(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewObjectDescriptor(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}
