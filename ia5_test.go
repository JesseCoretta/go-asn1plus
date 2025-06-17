package asn1plus

import (
	"fmt"
	"testing"
)

func TestNewIA5String_Valid(t *testing.T) {
	input := "Hello, world!"
	ia5, err := NewIA5String(input)
	if err != nil {
		t.Fatalf("NewIA5String(%q) returned error: %v", input, err)
	}
	if ia5.String() != input {
		t.Errorf("Expected IA5String.String() = %q, got %q", input, ia5.String())
	}
}

func TestNewIA5String_ByteSlice(t *testing.T) {
	input := []byte("Test string from []byte")
	ia5, err := NewIA5String(input)
	if err != nil {
		t.Fatalf("NewIA5String([]byte(%q)) returned error: %v", input, err)
	}
	if ia5.String() != string(input) {
		t.Errorf("Expected IA5String.String() = %q, got %q", string(input), ia5.String())
	}
}

func TestNewIA5String_Empty(t *testing.T) {
	_, err := NewIA5String("")
	if err == nil {
		t.Error("Expected error for empty string, got nil")
	}
}

func TestNewIA5String_InvalidType(t *testing.T) {
	_, err := NewIA5String(123)
	if err == nil {
		t.Error("Expected error for invalid type (int), got nil")
	}
}

func TestNewIA5String_InvalidCharacter(t *testing.T) {
	invalid := "AĀB"
	_, err := NewIA5String(invalid)
	if err == nil {
		t.Errorf("Expected error for IA5String with invalid character %q, got nil", invalid)
	}
}

func TestIA5String_IsZero(t *testing.T) {
	var s IA5String = ""
	if !s.IsZero() {
		t.Errorf("Expected IsZero() to return true for a zero IA5String")
	}

	s = IA5String("nonempty")
	if s.IsZero() {
		t.Errorf("Expected IsZero() to return false for a non-empty IA5String")
	}
}

func TestIA5String_String(t *testing.T) {
	input := "Example IA5 String"
	ia5, err := NewIA5String(input)
	if err != nil {
		t.Fatalf("Unexpected error for valid IA5String(%q): %v", input, err)
	}
	if ia5.String() != input {
		t.Errorf("IA5String.String() = %q, want %q", ia5.String(), input)
	}
}

func TestIA5String_Range(t *testing.T) {
	// Build a string containing runes from 0x00 to 0xFF.
	var validRunes []rune
	for r := rune(0x00); r <= 0xFF; r++ {
		validRunes = append(validRunes, r)
	}
	input := string(validRunes)
	ia5, err := NewIA5String(input)
	if err != nil {
		t.Fatalf("Expected valid IA5String for every rune between 0x00 and 0xFF, got error: %v", err)
	}
	if ia5.String() != input {
		t.Errorf("Expected IA5String.String() to return full valid range, got different result")
	}
}

func ExampleIA5String() {
	ia5, err := NewIA5String(`jesse.coretta@icloud.com`)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ia5)
	// Output: jesse.coretta@icloud.com
}

func ExampleIA5String_roundTripDER() {
	// Parse our ASN.1 IA5 STRING
	ia5, err := NewIA5String(`jesse.coretta@icloud.com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode our IA5String instance
	var der Packet
	if der, err = Marshal(ia5); err != nil {
		fmt.Println(err)
		return
	}

	// Decode our DER Packet into a new IA5String instance
	var other IA5String
	if err = Unmarshal(der, &other); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representations
	fmt.Printf("IA5Strings match: %t (%s)", ia5.String() == other.String(), ia5)
	// Output: IA5Strings match: true (jesse.coretta@icloud.com)
}

func TestIA5String_encodingRules(t *testing.T) {
	for _, value := range []any{
		"jesse.coretta@icloud.com",
	} {
		for _, rule := range encodingRules {
			// Parse our ASN.1 IA5 STRING
			ia5, err := NewIA5String(value)
			if err != nil {
				t.Fatalf("%s failed [New IA5String]: %v", t.Name(), err)
			}
			ia5.IsPrimitive()
			_ = ia5.String()
			ia5.Tag()

			// encode our IA5String instance
			var pkt Packet
			if pkt, err = Marshal(ia5, WithEncoding(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our Packet into a new IA5String instance
			var other IA5String
			if err = Unmarshal(pkt, &other); err != nil {
				t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			}

			// Compare string representations
			if ia5.String() != other.String() {
				t.Fatalf("%s failed [%s :: %T string cmp.]:\n\twant: '%s'\n\tgot:  '%s'",
					t.Name(), rule, ia5, ia5, other)
			}
		}
	}
}

func TestIA5String_codecov(_ *testing.T) {

	var ia5 IA5String
	ia5.Tag()
	ia5.read(&DERPacket{}, TLV{typ: BER, Class: 4, Tag: 2}, &Options{})
	ia5.read(&DERPacket{}, TLV{typ: BER, Class: 0, Tag: ia5.Tag(), Length: 100}, &Options{})

}

func ExampleIA5String_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o IA5String) IA5String { return o },
		func(o IA5String) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o IA5String) IA5String { return o },
		func(o IA5String) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewIA5String(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewIA5String(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}
