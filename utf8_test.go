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

	// DER encode UTF8String instance into Packet
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

func ExampleUTF8String_bER() {
	// Parse value into new UTF8String instance
	u8, err := NewUTF8String(`this is a UTF-8 string`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode UTF8String instance into Packet
	var pkt Packet
	if pkt, err = Marshal(u8, With(BER)); err != nil {
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

func TestNewUTF8String_DefaultValid(t *testing.T) {
	// A valid UTF-8 string.
	input := "Hello, 世界"
	u8, err := NewUTF8String(input)
	if err != nil {
		t.Fatalf("NewUTF8String(%q) returned error: %v", input, err)
	}
	if u8.String() != input {
		t.Errorf("Expected UTF8String.String() = %q, got %q", input, u8.String())
	}
	if u8.IsZero() {
		t.Error("Expected IsZero() to be false for a non-empty UTF8String")
	}
}

func TestNewUTF8String_DefaultInvalid(t *testing.T) {
	invalidBytes := []byte{0xff, 0xfe, 0xfd}
	_, err := NewUTF8String(invalidBytes)
	if err == nil {
		t.Errorf("Expected error for invalid UTF8 input %v, got nil", invalidBytes)
	}
}

func TestNewUTF8String_TypeConversion(t *testing.T) {
	inputStr := "Test"
	inputUTF8 := UTF8String(inputStr)
	u8, err := NewUTF8String(inputUTF8)
	if err != nil {
		t.Fatalf("NewUTF8String(UTF8String(%q)) returned error: %v", inputStr, err)
	}
	if u8.String() != inputStr {
		t.Errorf("Expected UTF8String from UTF8String = %q, got %q", inputStr, u8.String())
	}

	u8, err = NewUTF8String([]byte(inputStr))
	if err != nil {
		t.Fatalf("NewUTF8String([]byte(%q)) returned error: %v", inputStr, err)
	}
	if u8.String() != inputStr {
		t.Errorf("Expected UTF8String from []byte = %q, got %q", inputStr, u8.String())
	}
}

func TestNewUTF8String_InvalidType(t *testing.T) {
	_, err := NewUTF8String(12345)
	if err == nil {
		t.Error("Expected error for invalid type (int) for UTF8String, got nil")
	}
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

func TestUTF8String_Empty(t *testing.T) {
	emptyInput := ""
	u8, err := NewUTF8String(emptyInput)
	if err != nil {
		t.Fatalf("NewUTF8String(\"\") returned error: %v", err)
	}
	if u8.String() != emptyInput {
		t.Errorf("Expected UTF8String.String() to be empty, got %q", u8.String())
	}
	if !u8.IsZero() {
		t.Error("Expected IsZero() to return true for an empty UTF8String")
	}
}

func TestUTF8String_codecov(_ *testing.T) {
	u, _ := NewUTF8String(`stringvalue`)
	u.IsPrimitive()
	u.IsZero()
	u.Tag()
}
