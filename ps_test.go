package asn1plus

import "testing"

func TestNewPrintableStringValid(t *testing.T) {
	// Build a string that uses allowed characters.
	valid := "ABCabc0123 '()+,-./:?"
	ps, err := NewPrintableString(valid)
	if err != nil {
		t.Fatalf("NewPrintableString(%q) returned error: %v", valid, err)
	}
	if ps.String() != valid {
		t.Errorf("Expected PrintableString.String() = %q, got %q", valid, ps.String())
	}
}

func TestNewPrintableStringByteSlice(t *testing.T) {
	// Use a valid printable string as bytes. (Note that the exclamation mark is not allowed.)
	validStr := "Hello, World" // contains only allowed characters: letters, comma, and space.
	ps, err := NewPrintableString([]byte(validStr))
	if err != nil {
		t.Fatalf("NewPrintableString([]byte(%q)) returned error: %v", validStr, err)
	}
	if ps.String() != validStr {
		t.Errorf("Expected PrintableString.String() = %q, got %q", validStr, ps.String())
	}
}

func TestNewPrintableStringEmpty(t *testing.T) {
	_, err := NewPrintableString("")
	if err == nil {
		t.Error("Expected error for empty PrintableString input, got nil")
	}
}

func TestNewPrintableStringInvalidType(t *testing.T) {
	_, err := NewPrintableString(12345)
	if err == nil {
		t.Error("Expected error for invalid type (int) for PrintableString, got nil")
	}
}

func TestNewPrintableStringInvalidCharacter(t *testing.T) {
	invalid := "ABC@DEF"
	_, err := NewPrintableString(invalid)
	if err == nil {
		t.Errorf("Expected error for PrintableString input %q with invalid character, got nil", invalid)
	}
}

func TestPrintableStringMethods(t *testing.T) {
	input := "PrintableTest"
	ps, err := NewPrintableString(input)
	if err != nil {
		t.Fatalf("NewPrintableString(%q) returned error: %v", input, err)
	}

	if ps.String() != input {
		t.Errorf("Expected PrintableString.String() to return %q, got %q", input, ps.String())
	}

	if ps.IsZero() {
		t.Error("Expected IsZero() to return false for a non-empty PrintableString")
	}

	var emptyPS PrintableString = ""
	if !emptyPS.IsZero() {
		t.Error("Expected IsZero() to return true for an empty PrintableString")
	}
}

func TestPrintableString_encodingRules(t *testing.T) {
	for _, input := range []any{
		"PrintableTest",
	} {
		for _, rule := range encodingRules {
			ps, err := NewPrintableString(input)
			if err != nil {
				t.Fatalf("%s failed [%s NewPrintableString]: %v", t.Name(), rule, err)
			}

			var pkt Packet
			if pkt, err = Marshal(ps, WithEncoding(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			var ps2 PrintableString
			if err = Unmarshal(pkt, &ps2); err != nil {
				t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			}

			if ps.String() != ps2.String() {
				t.Fatalf("%s failed [%s string cmp.]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, ps, ps2)
			}
		}
	}
}

func TestPrintableString_codecov(_ *testing.T) {
	ps, _ := NewPrintableString(`Hello.`)
	ps.IsZero()
	ps.read(nil, TLV{Class: 2, Tag: ps.Tag()}, Options{})
	ps.read(nil, TLV{Class: 0, Tag: TagOID}, Options{})
	ps.read(&DERPacket{}, TLV{Class: 0, Tag: ps.Tag(), Length: 100}, Options{})
	_, _ = NewPrintableString(ps)
}
