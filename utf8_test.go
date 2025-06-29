package asn1plus

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func ExampleUTF8String() {
	u8, err := NewUTF8String(`this is a UTF-8 string`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(u8)
	// Output: this is a UTF-8 string
}

func ExampleUTF8String_dER() {
	// Parse value into new UTF8String instance
	u8, err := NewUTF8String(`this is a UTF-8 string`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode UTF8String instance into Packet. You
	// may substitute BER with another encoding rule,
	// if desired.
	var pkt Packet
	if pkt, err = Marshal(u8, With(DER)); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new UTF8String instance
	var ut UTF8String
	if err = Unmarshal(pkt, &ut); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", u8, u8.String() == ut.String(), ut)
	// Output: asn1plus.UTF8String values match: true (this is a UTF-8 string)

}

func mustContainNoDigits[T ~string]() Constraint[T] {
	return func(val T) (err error) {
		for _, char := range []rune(val) {
			if '0' <= char && char <= '9' {
				err = mkerr("Constraint violation: invalid ASN.1 UTF-8 codepoints found")
				break
			}
		}
		return
	}
}

/*
This example demonstrates the parsing of a UTF-8 STRING with a
constraining validator function employed.

Certain specifications which utilize the UTF-8 standard will
constrain the allowed characters (and/or character combinations)
to reject strings that would otherwise have been valid according
to UTF-8 alone.

The example constraint in this function simply rejects strings if
they contain any ASCII digits (0..9).

For the purposes of this example, the user should assume the following
function exists:

	func mustContainNoDigits[T ~string]() Constraint[T] {
	    return func(val T) (err error) {
	        for _, char := range []rune(val) {
	                if '0' <= char && char <= '9' {
	                        err = mkerr("Constraint violation: invalid ASN.1 UTF-8 codepoints found")
	                        break
	                }
	        }
	        return
	    }
	}
*/
func ExampleUTF8String_withConstraint() {
	numericalConstraint := LiftConstraint(func(o UTF8String) string {
		return string(o)
	}, mustContainNoDigits[string]())

	_, err := NewUTF8String(`this is a UTF-8 string`, numericalConstraint)
	fmt.Println(err)
	// Output: Constraint violation: invalid ASN.1 UTF-8 codepoints found
}

func TestNewUTF8String_constraint(t *testing.T) {
	// Step 1: Define the base validator as an anonymous function with concrete type string.
	baseValidator := func(s string) error {
		if !(utf8.ValidString(s) && !strings.Contains(s, "@")) {
			return mkerr("UTF-8 constraint violation")
		}
		return nil
	}

	// Step 2: Lift the base validator from Constraint[string] to Constraint[UTF8String].
	// Assuming UTF8String is defined as a type based on []byte or string.
	validator := LiftConstraint(func(u UTF8String) string {
		return string(u)
	}, baseValidator)

	validInput := "hello world"
	u8, err := NewUTF8String(validInput, validator)
	if err != nil {
		t.Fatalf("NewUTF8String(%q, custom) returned error: %v", validInput, err)
	}
	if u8.String() != validInput {
		t.Errorf("Expected UTF8String.String() = %q, got %q", validInput, u8.String())
	}

	invalidInput := "hello@world"
	_, err = NewUTF8String(invalidInput, validator)
	if err == nil {
		t.Errorf("Expected error for UTF8String input %q with '@' via custom validator, got nil", invalidInput)
	}
}

func TestUTF8String_codecov(t *testing.T) {
	u, _ := NewUTF8String(`stringvalue`)
	u.IsPrimitive()
	u.IsZero()
	u.Tag()
	u.Len()

	for _, valid := range []struct {
		value  any
		expect string
	}{
		{
			value:  []byte("Hello, 世界"),
			expect: "Hello, 世界",
		},
		{
			value:  "Hello, 世界",
			expect: "Hello, 世界",
		},
		{
			value:  OctetString("Hello, 世界"),
			expect: "Hello, 世界",
		},
	} {
		if p, err := NewUTF8String(valid.value); err != nil {
			t.Fatalf("NewUTF8String(%q) returned error: %v", valid.value, err)
		} else if p.String() != valid.expect {
			t.Fatalf("Expected UTF8String.String() = %q, got %q", valid.value, p.String())
		}
	}

	for _, bogus := range []any{
		[]byte{0xff, 0xfe, 0xfd},
		"",
		123456,
	} {
		if _, err := NewUTF8String(bogus); err == nil {
			t.Fatalf("%s: expected error for bogus %T (%v) input, got nil",
				t.Name(), bogus, bogus)
		}
	}
}

func BenchmarkUTF8StringConstructor(b *testing.B) {
	for _, value := range []any{
		"Hello, 世界",
		[]byte("Hello, 世界"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewUTF8String(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
