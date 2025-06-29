package asn1plus

import (
	"fmt"
	"testing"
)

func TestT61String_codecov(t *testing.T) {
	t61, _ := NewT61String("HELLO")
	t61.Tag()
	pkt, _ := Marshal(t61)
	var tt T61String
	_ = Unmarshal(pkt, &tt)

	for _, valid := range []struct {
		value  any
		expect string
	}{
		{
			value:  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			expect: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			value:  "HELLO 123",
			expect: "HELLO 123",
		},
		{
			value:  []byte("HELLO 123"),
			expect: "HELLO 123",
		},
	} {
		var err error
		if t61, err = NewT61String(valid.value); err != nil {
			t.Fatalf("%s failed: %v", t.Name(), err)
		} else if t61.String() != valid.expect {
			t.Fatalf("%s failed: expected T61String.String()=%q, got %q",
				t.Name(), valid.expect, t61.String())
		}
	}

	for _, bogus := range []any{
		"",
		"HELLO@WORLD",
		12345,
		nil,
	} {
		if _, err := NewT61String(bogus); err == nil {
			t.Fatalf("%s: expected error for bogus %T (%v) input, got nil",
				t.Name(), bogus, bogus)
		}
	}
}

func TestT61String_encodingRules(t *testing.T) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		T61String("objectName"),
	} {
		for _, rule := range encodingRules {
			// Parse our ASN.1 OCTET STRING
			od, err := NewT61String(value)
			if err != nil {
				t.Fatalf("%s failed [New T61String]: %v", t.Name(), err)
			}
			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our T61String instance
			var pkt Packet
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our Packet into a new T61String instance
			var other T61String
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

func ExampleT61String_withConstraint() {
	caseConstraint := LiftConstraint(func(o T61String) T61String { return o },
		func(o T61String) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	_, err := NewT61String(`this is a T.61 string`, caseConstraint)
	fmt.Println(err)
	// Output: Constraint violation: policy prohibits lower-case ASCII
}

func BenchmarkT61StringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		T61String("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewT61String(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
