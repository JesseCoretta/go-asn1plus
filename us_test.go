package asn1plus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestNewUniversalString_Valid(t *testing.T) {
	str := "Hello, 世界"
	us, err := NewUniversalString(str)
	if err != nil {
		t.Fatalf("NewUniversalString(%q) returned error: %v", str, err)
	}
	if us.String() != str {
		t.Errorf("Expected %q, got %q", str, us.String())
	}

	us2, err := NewUniversalString([]byte(str))
	if err != nil {
		t.Fatalf("NewUniversalString([]byte(%q)) returned error: %v", str, err)
	}
	if us2.String() != str {
		t.Errorf("Expected %q, got %q", str, us2.String())
	}

	us3, err := NewUniversalString(us)
	if err != nil {
		t.Fatalf("NewUniversalString(UniversalString(%q)) returned error: %v", str, err)
	}
	if us3.String() != str {
		t.Errorf("Expected %q, got %q", str, us3.String())
	}
}

func TestNewUniversalString_Invalid(t *testing.T) {
	// Construct an invalid UTF8 sequence.
	invalid := string([]byte{0x80, 0x80})
	_, err := NewUniversalString(invalid)
	if err == nil {
		t.Error("Expected error for invalid UTF8 input, got nil")
	}
}

func TestUniversalString_IsZero(t *testing.T) {
	var us UniversalString
	if !us.IsZero() {
		t.Error("Expected IsZero() to return true for empty UniversalString")
	}
}

func TestUniversalString_EncodingContentDER(t *testing.T) {
	str := "ABC"
	us, err := NewUniversalString(str)
	if err != nil {
		t.Fatalf("NewUniversalString(%q) failed: %v", str, err)
	}

	var pkt Packet
	if pkt, err = Marshal(us, WithEncoding(DER)); err != nil {
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
	if !bytes.Equal(expectedA, actualA) {
		t.Errorf("Expected first rune bytes %v, got %v", expectedA, actualA)
	}
}

func TestUniversalString_bER(t *testing.T) {
	original := "Hello, 世界"
	usOrig, err := NewUniversalString(original)
	if err != nil {
		t.Fatalf("NewUniversalString error: %v", err)
	}

	var pkt Packet
	if pkt, err = Marshal(usOrig, WithEncoding(BER)); err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	if len(pkt.Data()) < 2 {
		t.Fatalf("Packet data too short")
	}

	var usDecoded UniversalString
	if err = Unmarshal(pkt, &usDecoded); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if usDecoded.String() != original {
		t.Errorf("Roundtrip failed: expected %q, got %q", original, usDecoded.String())
	}
}

func TestUniversalString_dER(t *testing.T) {
	original := "Hello, 世界"
	usOrig, err := NewUniversalString(original)
	if err != nil {
		t.Fatalf("NewUniversalString error: %v", err)
	}

	var pkt Packet
	if pkt, err = Marshal(usOrig, WithEncoding(DER)); err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	if len(pkt.Data()) < 2 {
		t.Fatalf("Packet data too short")
	}

	var usDecoded UniversalString
	if err = Unmarshal(pkt, &usDecoded); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if usDecoded.String() != original {
		t.Errorf("Roundtrip failed: expected %q, got %q", original, usDecoded.String())
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

			var pkt Packet
			if pkt, err = Marshal(usOrig, WithEncoding(rule)); err != nil {
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

func TestDerUniversalString_InvalidLength(t *testing.T) {
	dp := &DERPacket{}
	invalidTLV := TLV{
		typ:      dp.Type(),
		Class:    ClassUniversal,
		Tag:      TagUniversalString,
		Compound: false,
		Length:   5, // Not a multiple of 4
	}
	dp.Append([]byte{0, 0, 0, 0, 0}...)
	var us UniversalString
	if err := us.read(dp, invalidTLV, Options{}); err == nil {
		t.Error("Expected error for invalid content length (not a multiple of 4), got nil")
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

	var pkt Packet
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
	if !bytes.Equal(ucs4Bytes, expected[:]) {
		t.Errorf("UCS-4 conversion error: expected %x, got %x", expected, ucs4Bytes)
	}
}

func TestUniversalString_codecov(_ *testing.T) {
	_, _ = NewUniversalString(struct{}{})

	us, _ := NewUniversalString("Hello, 世界")
	us.Tag()
	_ = us.String()
	us.IsPrimitive()
	us.Len()
	pkt, _ := Marshal(us)

	var us2 UniversalString
	_ = Unmarshal(pkt, &us2)

	us.read(nil, TLV{typ: pkt.Type(), Tag: us.Tag(), Length: 400}, Options{})
	us.read(pkt, TLV{typ: pkt.Type(), Tag: us.Tag(), Length: 400}, Options{})
	us.read(pkt, TLV{typ: pkt.Type(), Tag: us.Tag(), Length: 400, Value: []byte{byte(us.Tag()), 0x03, 0x1, 0x2, 0x3}}, Options{})
	us.read(pkt, TLV{typ: pkt.Type(), Tag: us.Tag(), Length: 3, Value: []byte{byte(us.Tag()), 0x03, 0x1, 0x2, 0x3}}, Options{})
}

func ExampleUniversalString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o UniversalString) UniversalString { return o },
		func(o UniversalString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o UniversalString) UniversalString { return o },
		func(o UniversalString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

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
