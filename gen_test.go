//go:build !asn1_no_dprc

package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewGeneralString_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()
	_ = MustNewGeneralString(struct{}{})
}

func ExampleGeneralString() {
	vs, err := NewGeneralString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vs)
	// Output: Jesse
}

func ExampleGeneralString_bER() {
	// Parse string into a GeneralString instance
	vs, err := NewGeneralString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// BER encode GeneralString into PDU instance
	var der PDU
	if der, err = Marshal(vs, With(BER)); err != nil {
		fmt.Println(err)
		return
	}

	// Decode BER PDU into new GeneralString instance
	var vs2 GeneralString
	if err = Unmarshal(der, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", vs, vs.String() == vs2.String(), vs2)
	// Output: asn1plus.GeneralString values match: true (Jesse)
}

func TestGeneralString_codecov(_ *testing.T) {
	var od GeneralString
	od.Tag()
	od.Len()
	od.IsPrimitive()
	_ = od.String()

	GeneralSpec(``)
	GeneralSpec(`test`)
	GeneralSpec([]byte(`test`))
	GeneralSpec(struct{}{})

	_, _ = NewGeneralString(nil)
	_, _ = NewGeneralString(string(rune(2)))
	_, _ = NewGeneralString(struct{}{})
	GeneralSpec(GeneralString(string(rune(0xFFFFFF))))
}

func TestGeneralString_encodingRules(t *testing.T) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		GeneralString("objectName"),
	} {
		for _, rule := range encodingRules {
			od, err := NewGeneralString(value)
			if err != nil {
				t.Fatalf("%s failed [New GeneralString]: %v", t.Name(), err)
			}

			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our GeneralString instance
			var pkt PDU
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our PDU into a new GeneralString instance
			var other GeneralString
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

func ExampleGeneralString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := func(x any) (err error) {
		o, _ := x.(GeneralString)
		for i := 0; i < len(o); i++ {
			if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
				err = fmt.Errorf("Constraint violation: policy prohibits digits")
				break
			}
		}
		return
	}

	// Prohibit any lower-case ASCII letters
	caseConstraint := func(x any) (err error) {
		o, _ := x.(GeneralString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewGeneralString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewGeneralString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}

func BenchmarkGeneralStringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		GeneralString("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewGeneralString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
