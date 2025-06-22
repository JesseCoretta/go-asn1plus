package asn1plus

import (
	"fmt"
	"testing"
)

func TestNewT61String_Valid(t *testing.T) {
	input := "HELLO 123" // H, E, L, L, O, space, 1,2,3 – all within allowed ranges.
	t61, err := NewT61String(input)
	if err != nil {
		t.Fatalf("NewT61String(%q) unexpected error: %v", input, err)
	}
	if t61.String() != input {
		t.Errorf("Expected T61String.String()=%q, got %q", input, t61.String())
	}
}

func TestNewT61String_ByteSlice(t *testing.T) {
	input := []byte("WORLD 456")
	t61, err := NewT61String(input)
	if err != nil {
		t.Fatalf("NewT61String([]byte(%q)) unexpected error: %v", input, err)
	}
	if t61.String() != string(input) {
		t.Errorf("Expected T61String.String()=%q, got %q", string(input), t61.String())
	}
}

func TestNewT61String_Empty(t *testing.T) {
	_, err := NewT61String("")
	if err == nil {
		t.Error("Expected error for empty T61String input, got nil")
	}
}

func TestNewT61String_InvalidType(t *testing.T) {
	_, err := NewT61String(12345)
	if err == nil {
		t.Error("Expected error for invalid type (int) for T61String, got nil")
	}
}

func TestNewT61String_InvalidCharacter(t *testing.T) {
	// Use a valid T.61 string and inject an illegal character.
	invalid := "HELLO@WORLD"
	_, err := NewT61String(invalid)
	if err == nil {
		t.Errorf("Expected error for T61String input %q with invalid character, got nil", invalid)
	}
}

func TestT61String_StringAndIsZero(t *testing.T) {
	valid := "TELETEX"
	t61, err := NewT61String(valid)
	if err != nil {
		t.Fatalf("NewT61String(%q) unexpected error: %v", valid, err)
	}
	if t61.String() != valid {
		t.Errorf("T61String.String() = %q, want %q", t61.String(), valid)
	}
	if t61.IsZero() {
		t.Error("Expected IsZero() to return false for a non-empty T61String")
	}

	// Test an explicit empty conversion (should be considered zero).
	var empty T61String = ""
	if !empty.IsZero() {
		t.Error("Expected IsZero() to return true for empty T61String")
	}
}

func TestT61String_AllowedCharacters(t *testing.T) {
	// Build a string from allowed ranges. We
	// know that uppercase letters "A" (0x41)
	// to "Z" (0x5A) are allowed as per t61Ranges.
	s := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	t61, err := NewT61String(s)
	if err != nil {
		t.Fatalf("NewT61String(%q) returned error: %v", s, err)
	}
	if t61.String() != s {
		t.Errorf("Expected T61String.String()=%q, got %q", s, t61.String())
	}
}

func TestT61String_codecov(_ *testing.T) {
	t61, _ := NewT61String("HELLO")
	t61.Tag()
	pkt, _ := Marshal(t61)
	var tt T61String
	_ = Unmarshal(pkt, &tt)
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
