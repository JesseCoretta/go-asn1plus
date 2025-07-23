package asn1plus

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestUniversalString_EncodingContentBER(t *testing.T) {
	str := "ABC"
	us, err := NewUniversalString(str)
	if err != nil {
		t.Fatalf("NewUniversalString(%q) failed: %v", str, err)
	}

	var pkt PDU
	if pkt, err = Marshal(us, With(BER)); err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	// "ABC" has 3 runes, each encoded as 4 bytes, so content length should be 12 bytes.
	expectedContentLen := 12
	expectedTotal := expectedContentLen + 2
	if len(pkt.Data()) != expectedTotal {
		t.Errorf("Expected total length %d, got %d", expectedTotal, len(pkt.Data()))
	}
	// Check header: dp.data[0] should equal TagUniversalString and dp.data[1] the content length.
	if pkt.Data()[0] != byte(TagUniversalString) {
		t.Errorf("Expected tag 0x%X, got 0x%X", TagUniversalString, pkt.Data()[0])
	}
	if pkt.Data()[1] != byte(expectedContentLen) {
		t.Errorf("Expected length %d, got %d", expectedContentLen, pkt.Data()[1])
	}
	// Verify first rune "A" (0x41). In UCS-4 big-endian: 0x00 0x00 0x00 0x41.
	expectedA := []byte{0, 0, 0, 0x41}
	actualA := pkt.Data()[2:6]
	if !btseq(expectedA, actualA) {
		t.Errorf("Expected first rune bytes %v, got %v", expectedA, actualA)
	}
}

func TestUniversalString_encodingRules(t *testing.T) {
	for _, value := range []any{
		"Hello, 世界",
	} {
		for _, rule := range encodingRules {
			usOrig, err := NewUniversalString(value)
			if err != nil {
				t.Fatalf("%s failed [%s NewUniversalString] error: %v", t.Name(), rule, err)
			}

			var pkt PDU
			if pkt, err = Marshal(usOrig, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			var usDecoded UniversalString
			if err = Unmarshal(pkt, &usDecoded); err != nil {
				t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			} else if usDecoded.String() != value {
				t.Fatalf("%s failed [%s string cmp.]:\n\twant: %q\n\tgot:  %q",
					t.Name(), rule, value, usDecoded.String())
			}
		}
	}
}

func TestUniversalString_UCS4Conversion(t *testing.T) {
	input := "😀"
	us, err := NewUniversalString(input)
	if err != nil {
		t.Fatalf("NewUniversalString(%q) failed: %v", input, err)
	}
	// Check that the input is valid UTF8.
	if !utf8OK(input) {
		t.Fatal("Input string is not valid UTF8")
	}

	var pkt PDU
	if pkt, err = Marshal(us); err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	// The UCS-4 encoding for U+1F600 (grinning face) should be 4 bytes.
	if len(pkt.Data()) < 6 {
		t.Fatalf("Encoded data too short, length %d", len(pkt.Data()))
	}
	// Skip the 2-byte header.
	ucs4Bytes := pkt.Data()[2:6]
	// Compute expected 4-byte sequence.
	var expected [4]byte
	// U+1F600 in hex: 0x0001F600
	binary.BigEndian.PutUint32(expected[:], uint32(0x1F600))
	if !btseq(ucs4Bytes, expected[:]) {
		t.Errorf("UCS-4 conversion error: expected %x, got %x", expected, ucs4Bytes)
	}
}

func TestUniversalString_codecov(t *testing.T) {
	_, _ = NewUniversalString(struct{}{})

	us, _ := NewUniversalString("Hello, 世界")
	if us.IsZero() {
		t.Fatalf("Expected IsZero() to return true for empty UniversalString")
	}

	UniversalSpec(`test`)
	UniversalSpec([]byte(`test`))
	UniversalSpec(struct{}{})

	us.Tag()
	_ = us.String()
	us.IsPrimitive()
	us.Len()
	pkt, _ := Marshal(us)

	var us2 UniversalString
	_ = Unmarshal(pkt, &us2)

	var us3 UniversalString = UniversalString(string([]rune{0xD800}))
	encodeUniversalString(us3)
	universalStringDecoderVerify([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	universalStringDecoderVerify([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	universalStringCharacterOutOfBounds(0xFFFFFFA)

	us3 = UniversalString(string([]rune{0xFF, 0xFF, 0xFF, 0xFF}))
	_ = us3.String()

	us3 = UniversalString(string([]rune{0x0E, 0x1A, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}))
	_ = us3.String()

	us3 = UniversalString([]byte{0x00, 0x00, 0x00, 0x41})
	_ = us3.String()

	encodeUniversalString(UniversalString([]byte{0xFF}))

	badRune := uint32(0xD800)
	b := []byte{
		byte(badRune >> 24),
		byte(badRune >> 16),
		byte(badRune >> 8),
		byte(badRune),
	}
	_ = UniversalString(b).String()

	for _, valid := range []struct {
		value  any
		expect string
	}{
		{
			value:  "Hello, 世界",
			expect: "Hello, 世界",
		},
		{
			value:  OctetString("Hello, 世界"),
			expect: "Hello, 世界",
		},
	} {
		if p, err := NewUniversalString(valid.value); err != nil {
			t.Fatalf("NewUniversalString(%q) returned error: %v", valid.value, err)
		} else if p.String() != valid.expect {
			t.Fatalf("Expected UniversalString.String() = %q, got %q", valid.value, p.String())
		}
	}

	for _, bogus := range []any{
		[]byte{0x80, 0x80},
	} {
		if _, err := NewUniversalString(bogus); err == nil {
			t.Fatalf("%s: expected error for bogus %T (%v) input, got nil",
				t.Name(), bogus, bogus)
		}
	}

}

func ExampleUniversalString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := func(x any) (err error) {
		o, _ := x.(UniversalString)
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
		o, _ := x.(UniversalString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewUniversalString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewUniversalString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}

func BenchmarkUniversalStringConstructor(b *testing.B) {
	for _, value := range []any{
		"Hello, 世界",
		[]byte("Hello, 世界"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewUniversalString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
