//go:build !asn1_no_dprc

package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleChoice_invalidChoice() {
	// Create an ASN.1 BIT STRING (tag 3), which is
	// INAPPROPRIATE for a DirectoryString.
	bs, err := NewBitString(`'1010011'B`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create our ASN.1 CHOICE(s) per the X.501
	// schema definition.
	directoryString := NewChoices()
	directoryString.Register(new(T61String))
	directoryString.Register(new(PrintableString))
	directoryString.Register(new(BMPString))
	directoryString.Register(new(UniversalString))
	directoryString.Register(new(UTF8String))

	if _, err = directoryString.Choose(bs); err != nil {
		fmt.Println(err)
	}
	// Output: no matching alternative found for input type asn1plus.BitString
}

/*
This example demonstrates the creation of the following ASN.1 CHOICE per [ITU-T Rec. X.501].

	DirectoryString{INTEGER:maxSize} ::= CHOICE {
	        teletexString TeletexString(SIZE (1..maxSize,...)),
	        printableString PrintableString(SIZE (1..maxSize,...)),
	        bmpString BMPString(SIZE (1..maxSize,...)),
	        universalString UniversalString(SIZE (1..maxSize,...)),
	        uTF8String UTF8String(SIZE (1..maxSize,...)) }

Following this, a [T61String] is chosen from our available directory string choices.

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func ExampleChoice_t61DirectoryStringDER() {
	// Marshal new T61String
	t61, err := NewT61String(`HELLO WORLD`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create our ASN.1 CHOICE(s)
	directoryString := NewChoices()
	_ = directoryString.Register(new(T61String))
	_ = directoryString.Register(new(PrintableString))
	_ = directoryString.Register(new(BMPString))
	_ = directoryString.Register(new(UniversalString))
	_ = directoryString.Register(new(UTF8String))

	// Choose our DirectoryString if the
	// T.61 tag (20) is matched
	var choice Choice
	if choice, err = directoryString.Choose(t61); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(choice.Value)
	// Output: HELLO WORLD
}

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
			var pkt PDU
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our PDU into a new T61String instance
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
