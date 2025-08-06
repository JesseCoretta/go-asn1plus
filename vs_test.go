package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewVisibleString_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()
	_ = MustNewVisibleString(struct{}{})
}

func ExampleVisibleString() {
	vs, err := NewVisibleString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vs)
	// Output: Jesse
}

func ExampleVisibleString_withConstraint() {
	caseConstraint := func(x any) (err error) {
		o, _ := x.(VisibleString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	_, err := NewVisibleString(`this is a VISIBLE STRING`, caseConstraint)
	fmt.Println(err)
	// Output: Constraint violation: policy prohibits lower-case ASCII
}

func ExampleVisibleString_bER() {
	// Parse string into a VisibleString instance
	vs, err := NewVisibleString("Jesse")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode VisibleString into PDU instance.
	// If desired, substitute BER with another encoding
	// rule.
	var pkt PDU
	if pkt, err = Marshal(vs, With(BER)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%T Hex: %s\n", pkt, pkt.Hex())

	// Decode DER PDU into new VisibleString instance
	var vs2 VisibleString
	if err = Unmarshal(pkt, &vs2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", vs, vs.String() == vs2.String(), vs2)
	// Output:
	// *asn1plus.BERPacket Hex: 1A 05 4A65737365
	// asn1plus.VisibleString values match: true (Jesse)
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
			vs.Len()
			vs.IsZero()
			vs.IsPrimitive()
			_ = vs.String()

			var pkt PDU
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

	VisibleSpec(`test`)
	VisibleSpec([]byte(`test`))
	VisibleSpec(struct{}{})

	NewVisibleString([]byte{0x7F, 0x7F, 0x08})
	_, _ = NewVisibleString(struct{}{})
}

func BenchmarkVisibleStringConstructor(b *testing.B) {
	for _, value := range []any{
		"Hello, 世界",
		[]byte("Hello, 世界"),
		VisibleString("Hello, 世界"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewVisibleString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
