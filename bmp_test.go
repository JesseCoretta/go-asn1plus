package asn1plus

import (
	"fmt"
	"testing"
)

func equalBMPString(a, b BMPString) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ExampleBMPString() {
	// Parse our ASN.1 BMP STRING
	bmp, err := NewBMPString(`HELLO Σ`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// If non-zero, show the string representation
	// of our new ASN.1 BMP STRING instance.
	if !bmp.IsZero() {
		fmt.Println(bmp)
	}
	// Output: HELLO Σ
}

func ExampleBMPString_roundTripBER() {
	// Parse our ASN.1 BMP STRING
	bmp, err := NewBMPString(`HELLO Σ`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// BER encode our ASN.1 BMP STRING instance
	// into a Packet
	var pkt Packet
	if pkt, err = Marshal(bmp, WithEncoding(BER)); err != nil {
		fmt.Println(err)
		return
	}

	// Create a new receiver for BER decoded BMP data
	// derived from our BER packet.
	var bmp2 BMPString
	if err = Unmarshal(pkt, &bmp2); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Values match: %t (%s)", bmp.String() == bmp2.String(), bmp)
	// Output: Values match: true (HELLO Σ)
}

func ExampleBMPString_roundTripDER() {
	// Parse our ASN.1 BMP STRING
	bmp, err := NewBMPString(`HELLO Σ`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode our ASN.1 BMP STRING instance
	// into a Packet
	var pkt Packet
	if pkt, err = Marshal(bmp, WithEncoding(DER)); err != nil {
		fmt.Println(err)
		return
	}

	// Create a new receiver for DER decoded BMP data
	// derived from our DER packet.
	var bmp2 BMPString
	if err = Unmarshal(pkt, &bmp2); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Values match: %t (%s)", bmp.String() == bmp2.String(), bmp)
	// Output: Values match: true (HELLO Σ)
}

func TestBMPString_codecov(t *testing.T) {

	results := []string{
		"Σ",
		"HELLO",
		"ABC",
		"HELΣLO",
		"",
		"",
	}

	for idx, encoded := range []BMPString{
		{0x1e, 0x1, 0x3, 0xa3}, // sigma Σ
		{0x1e, 0x5, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x0, 0x4c, 0x0, 0x4f},            // HELLO
		{0x1e, 0x3, 0x0, 0x41, 0x0, 0x42, 0x0, 0x43},                                  // ABC
		{0x1e, 0x6, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x3, 0xa3, 0x0, 0x4c, 0x0, 0x4f}, // HELΣLO
		{0x1e, 0x0}, // empty-ish
		{},          // really empty
	} {
		if decoded := encoded.String(); decoded != results[idx] {
			t.Errorf("%s[%d] stringer failed:\nwant: %#v\ngot:  %#v",
				t.Name(), idx, results[idx], decoded)
		}
	}

	for idx, decoded := range results {
		if encoded, err := NewBMPString(decoded); err != nil {
			t.Errorf("ENCODE: %s[%d] failed: %v",
				t.Name(), idx, err)
		} else if reenc := encoded.String(); reenc != results[idx] {
			t.Errorf("ENCODE: %s[%d] failed:\nwant:%#v [%d]\ngot: %#v [%d]",
				t.Name(), idx, decoded, len(decoded),
				results[idx], len(results[idx]))
		}
	}

	NewBMPString(struct{}{})
	NewBMPString(BMPString{})
	NewBMPString(BMPString{0x1e, 0x1, 0x1, 0xef})
	NewBMPString(BMPString{0x1e, 0x1, 0x1, 0xef})
	NewBMPString(BMPString{0x1f, 0x1, 0x1, 0xef})
	NewBMPString(BMPString{0x1e, 0xe})
	NewBMPString(BMPString{0x1f, 0x0})
	NewBMPString(BMPString{0x1e, 0x0})

	b := BMPString{0x1e, 0x5, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x0, 0x4c, 0x0, 0x4f}
	b.read(nil, TLV{typ: DER, Class: 5, Tag: TagBMPString}, &Options{})
	b.read(&DERPacket{offset: 5}, TLV{typ: DER, Class: 0, Tag: TagBMPString}, &Options{})
	b.Tag()
	b.Len()
	b.IsPrimitive()
	_, _ = Marshal(b)

}

func TestNewBMPString_FromString(t *testing.T) {
	input := "A"
	bmp, err := NewBMPString(input)
	if err != nil {
		t.Fatalf("NewBMPString(%q) returned error: %v", input, err)
	}
	expected := BMPString{0x1E, 0x01, 0x00, 0x41}
	if !equalBMPString(bmp, expected) {
		t.Errorf("NewBMPString(%q) = %v; want %v", input, bmp, expected)
	}
	if s := bmp.String(); s != input {
		t.Errorf("BMPString.String() = %q; want %q", s, input)
	}
}

func TestNewBMPString_EmptyString(t *testing.T) {
	input := ""
	bmp, err := NewBMPString(input)
	if err != nil {
		t.Fatalf("NewBMPString(\"\") returned error: %v", err)
	}
	expected := BMPString{0x1E, 0x0}
	if !equalBMPString(bmp, expected) {
		t.Errorf("NewBMPString(\"\") = %v; want %v", bmp, expected)
	}
	if s := bmp.String(); s != "" {
		t.Errorf("BMPString.String() = %q; want empty string", s)
	}
}

func TestNewBMPString_FromBytes(t *testing.T) {
	input := "Hi"
	bmp1, err := NewBMPString(input)
	if err != nil {
		t.Fatalf("NewBMPString(%q) returned error: %v", input, err)
	}
	bmp2, err := NewBMPString([]uint8(input))
	if err != nil {
		t.Fatalf("NewBMPString([]uint8(%q)) returned error: %v", input, err)
	}
	if bmp1.String() != bmp2.String() {
		t.Errorf("BMPString from string and []uint8 differ: %q vs. %q", bmp1.String(), bmp2.String())
	}
}

func TestNewBMPString_TooLong(t *testing.T) {
	bld := newStrBuilder()
	for i := 0; i < 256; i++ {
		bld.WriteByte('A')
	}
	longStr := bld.String()
	_, err := NewBMPString(longStr)
	if err == nil {
		t.Errorf("Expected error when encoding a BMPString longer than 255 units, but got nil")
	}
}

func TestNewBMPString_FromBMPStringValue(t *testing.T) {
	original, err := NewBMPString("Test")
	if err != nil {
		t.Fatalf("NewBMPString(\"Test\") returned error: %v", err)
	}
	bmp, err := NewBMPString(original)
	if err != nil {
		t.Fatalf("NewBMPString(BMPString) returned error: %v", err)
	}
	if bmp.String() != "Test" {
		t.Errorf("BMPString.String() = %q; want \"Test\"", bmp.String())
	}
}

func TestNewBMPString_InvalidTag(t *testing.T) {
	invalid := BMPString{0x00, 0x01, 0x00, 0x41}
	_, err := NewBMPString(invalid)
	if err == nil {
		t.Errorf("Expected error for BMPString with invalid tag, got nil")
	}
}

func TestNewBMPString_InvalidLengthOctet(t *testing.T) {
	invalid := BMPString{0x1E, 0x02, 0x00, 0x41}
	_, err := NewBMPString(invalid)
	if err == nil {
		t.Errorf("Expected error for BMPString with mismatched length octet, got nil")
	}
}

func TestBMPString_StringMethod(t *testing.T) {
	input := "Hello, BMP!"
	bmp, err := NewBMPString(input)
	if err != nil {
		t.Fatalf("NewBMPString(%q) returned error: %v", input, err)
	}
	output := bmp.String()
	if output != input {
		t.Errorf("BMPString.String() = %q; want %q", output, input)
	}
}

func TestBMPString_UTF16Encoding(t *testing.T) {
	input := "漢"
	bmp, err := NewBMPString(input)
	if err != nil {
		t.Fatalf("NewBMPString(%q) returned error: %v", input, err)
	}
	encoded := utf16Enc([]rune(input))
	length := len(encoded)
	expected := []byte{0x1E, byte(length)}
	for _, codeUnit := range encoded {
		expected = append(expected, byte(codeUnit>>8), byte(codeUnit&0xFF))
	}
	if !equalBMPString(bmp, expected) {
		t.Errorf("BMPString encoding = %v; want %v", bmp, expected)
	}
}

func ExampleBMPString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o BMPString) BMPString { return o },
		func(o BMPString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o BMPString) BMPString { return o },
		func(o BMPString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewBMPString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewBMPString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}
