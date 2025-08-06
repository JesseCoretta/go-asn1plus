//go:build !asn1_no_dprc

package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewGraphicString_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()
	_ = MustNewGraphicString(struct{}{})
}

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

	// DER encode GraphicString into PDU instance
	var der PDU
	if der, err = Marshal(vs); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER PDU into new GraphicString instance
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

	GraphicSpec(``)
	GraphicSpec(`test`)
	GraphicSpec([]byte(`test`))
	GraphicSpec(struct{}{})

	_, _ = NewGraphicString(nil)
	_, _ = NewGraphicString(string(rune(2)))
	_, _ = NewGraphicString(struct{}{})
	graphicStringDecoderVerify([]byte{0x08})
	graphicStringDecoderVerify([]byte{byte(string(rune(127))[0])})

	badRune := uint32(0xD800)
	b := []byte{
		byte(badRune >> 24),
		byte(badRune >> 16),
		byte(badRune >> 8),
		byte(badRune),
	}
	graphicStringDecoderVerify(b)
	graphicStringDecoderVerify([]byte{0x30})
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
			var pkt PDU
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our PDU into a new GraphicString instance
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
	digitConstraint := func(x any) (err error) {
		o, _ := x.(GraphicString)
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
		o, _ := x.(GraphicString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

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

func BenchmarkGraphicStringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		GraphicString("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewGraphicString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
