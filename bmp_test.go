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

func ExampleBMPString_roundTripBER() {
	// Parse our ASN.1 BMP STRING
	bmp, err := NewBMPString(`HELLO Σ`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// BER encode our ASN.1 BMP STRING instance
	// into a Packet. Alternatively, substitute
	// BER with another encoding rule if desired.
	var pkt Packet
	if pkt, err = Marshal(bmp, With(BER)); err != nil {
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

	//NewBMPString(struct{}{})
	//NewBMPString(BMPString{})
	//NewBMPString(BMPString{0x1e, 0x1, 0x1, 0xef})
	//NewBMPString(BMPString{0x1e, 0x1, 0x1, 0xef})
	//NewBMPString(BMPString{0x1f, 0x1, 0x1, 0xef})
	//NewBMPString(BMPString{0x1e, 0xe})
	//NewBMPString(BMPString{0x1f, 0x0})
	//NewBMPString(BMPString{0x1e, 0x0})

	buildBMP(``)
	//NewBMPString(OctetString("test"))
	b := BMPString{0x1e, 0x5, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x0, 0x4c, 0x0, 0x4f}
	b.IsZero()
	b.Tag()
	b.Len()
	b.IsPrimitive()
	_, _ = Marshal(b)

	for idx, valid := range []struct {
		value  any
		expect BMPString
	}{
		{
			value:  "A",
			expect: BMPString{0x1E, 0x01, 0x00, 0x41},
		},
		{
			value:  "",
			expect: BMPString{0x1E, 0x00},
		},
		{
			value:  []byte("Hi"),
			expect: BMPString{0x1E, 0x02, 0x00, 0x48, 0x00, 0x69},
		},
		{
			value:  BMPString{0x1E, 0x02, 0x00, 0x48, 0x00, 0x69},
			expect: BMPString{0x1E, 0x02, 0x00, 0x48, 0x00, 0x69},
		},
		{
			value:  BMPString{0x1E, 0x00},
			expect: BMPString{0x1E, 0x0},
		},
		{
			value:  BMPString{},
			expect: BMPString{0x1E, 0x0},
		},
		{
			value:  OctetString("Hi"),
			expect: BMPString{0x1E, 0x02, 0x00, 0x48, 0x00, 0x69},
		},
		{
			value:  "",
			expect: BMPString{0x1E, 0x00},
		},
	} {
		if bmp, err := NewBMPString(valid.value); err != nil {
			t.Fatalf("%s[%d]: NewBMPString(%v) returned error: %v", t.Name(), idx, valid.value, err)
		} else {
			if idx == 3 {
				t.Logf("actual: %#v\n", bmp)
				t.Logf("expect: %#v\n", valid.expect)
			}
			if !equalBMPString(bmp, valid.expect) {
				t.Fatalf("%s[%d]: NewBMPString(%v) = len(%d); want len(%d)", t.Name(), idx, valid.value, bmp.Len(), valid.expect.Len())
			}
		}
	}

	tooLong := newStrBuilder()
	for i := 0; i < 256; i++ {
		tooLong.WriteByte('A')
	}

	for idx, bogus := range []struct {
		value  any
		expect string
	}{
		{
			value:  tooLong.String(),
			expect: "too long error",
		},
		{
			value:  BMPString{0x00, 0x00},
			expect: "invalid BMP string length octet error",
		},
		{
			value:  BMPString{0x00, 0x01, 0x00, 0x41},
			expect: "invalid BMP string tag error",
		},
		{
			value:  BMPString{0x1E, 0x02, 0x00, 0x41},
			expect: "invalid BMP string length octet error",
		},
		{
			value:  struct{}{},
			expect: "invalid ASN.1 BMP STRING error",
		},
	} {
		if _, err := NewBMPString(bogus.value); err == nil {
			t.Fatalf("%s[%d]: expected %q for bogus %T, got nil", t.Name(), idx, bogus.expect, bogus.value)
		}
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
