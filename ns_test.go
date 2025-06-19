package asn1plus

import (
	"fmt"
	"testing"
)

func TestConvertToNumericString(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		expected  string
		expectErr bool
	}{
		{"int valid", 123, "123", false},
		{"int8 valid", int8(45), "45", false},
		{"int16 valid", int16(6789), "6789", false},
		{"int32 valid", int32(98765), "98765", false},
		{"int64 valid", int64(1234567890), "1234567890", false},
		{"uint valid", uint(42), "42", false},
		{"uint8 valid", uint8(99), "99", false},
		{"uint16 valid", uint16(1000), "1000", false},
		{"uint32 valid", uint32(123456), "123456", false},
		{"uint64 valid", uint64(987654321), "987654321", false},
		{"string valid", "123 456", "123 456", false},
		{"empty string", "", "", true},
		{"negative int", -123, "", true},
		{"negative int8", int8(-5), "", true},
		{"invalid type", 3.14, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToNumericString(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("convertToNumericString(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("convertToNumericString(%v) unexpected error: %v", tt.input, err)
				} else if got != tt.expected {
					t.Errorf("convertToNumericString(%v) = %q, want %q", tt.input, got, tt.expected)
				}
			}
		})
	}
}

func TestNewNumericString(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		expected  string
		expectErr bool
	}{
		{"numeric from int", 789, "789", false},
		{"numeric from uint", uint(456), "456", false},
		{"numeric from string valid", "123 456", "123 456", false},
		{"numeric from string only digits", "987654321", "987654321", false},
		{"numeric from string with space", "  ", "  ", false},
		{"invalid string (illegal char)", "12A34", "", true},
		{"empty string input", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := NewNumericString(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("NewNumericString(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("NewNumericString(%v) unexpected error: %v", tt.input, err)
				} else if string(ns) != tt.expected {
					t.Errorf("NewNumericString(%v) = %q, want %q", tt.input, ns, tt.expected)
				}
			}
		})
	}
}

func TestNumericString_String(t *testing.T) {
	ns := NumericString("123 456")
	ns.IsZero()
	if ns.String() != "123 456" {
		t.Errorf("NumericString.String() = %q, want %q", ns.String(), "123 456")
	}
}

func TestNumericString_codecov(_ *testing.T) {
	var ns NumericString
	ns.Tag()
}

func ExampleNumericString_dER() {
	// Parse value into new NumericString instance
	ns, err := NewNumericString("0 123 456 789")
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode NumericString instance
	var pkt Packet
	if pkt, err = Marshal(ns, With(DER)); err != nil {
		fmt.Println(err)
		return
	}

	// Decode DER Packet into new NumericString instance
	var ns2 NumericString
	if err = Unmarshal(pkt, &ns2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", ns, ns.String() == ns2.String(), ns)
	// Output: asn1plus.NumericString values match: true (0 123 456 789)
}

func TestNumericString_encodingRules(t *testing.T) {
	for idx, value := range []any{
		"00 18928 1",
		"1488945",
		1488945,
		NumericString("00 18928 1"),
	} {
		for _, rule := range encodingRules {
			// Parse our ASN.1 NUMERIC STRING
			od, err := NewNumericString(value)
			if err != nil {
				t.Fatalf("%s[%d] failed [New NumericString]: %v", t.Name(), idx, err)
			}
			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our NumericString instance
			var pkt Packet
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s[%d] failed [%s encoding]: %v", t.Name(), idx, rule, err)
			}
			t.Logf("%T.%s hex::%s\n", od, rule, pkt.Hex())

			// Decode our Packet into a new NumericString instance
			var other NumericString
			if err = Unmarshal(pkt, &other); err != nil {
				t.Fatalf("%s[%d] failed [%s decoding]: %v", t.Name(), idx, rule, err)
			}

			// Compare string representations
			if od.String() != other.String() {
				t.Fatalf("%s[%d] failed [%s :: %T string cmp.]:\n\twant: '%s'\n\tgot:  '%s'",
					t.Name(), idx, rule, od, od, other)
			}
		}
	}
}
