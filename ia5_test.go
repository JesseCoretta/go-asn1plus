package asn1plus

import (
	"fmt"
	"testing"
)

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
	var der PDU
	if der, err = Marshal(ia5); err != nil {
		fmt.Println(err)
		return
	}

	// Decode our DER PDU into a new IA5String instance
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
		[]byte("jesse.coretta@icloud.com"),
		IA5String("jesse.coretta@icloud.com"),
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
			var pkt PDU
			if pkt, err = Marshal(ia5, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our PDU into a new IA5String instance
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

func TestIA5String_codecov(t *testing.T) {
	var ia5 IA5String
	ia5.Tag()
	ia5.Len()
	ia5.IsZero()
	ia5.IsPrimitive()
	_ = ia5.String()
	NewIA5String(ia5)

	IA5Spec(``)
	IA5Spec(`test`)
	IA5Spec([]byte(`test`))
	IA5Spec(struct{}{})

	for _, bogus := range []any{
		"",    // Zero len
		123,   // Not a string, []byte or ASN.1 Primitive
		"AĀB", // Outside of allowed 0x00:0xFF range
	} {
		if _, err := NewIA5String(bogus); err == nil {
			t.Fatalf("%s: expected error for bogus %T value (%v), got nil",
				t.Name(), bogus, bogus)
		}
	}
}

func ExampleIA5String_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := func(x any) (err error) {
		o, _ := x.(IA5String)
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
		o, _ := x.(IA5String)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

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

func BenchmarkIA5StringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		IA5String("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewIA5String(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
