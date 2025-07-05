package asn1plus

import (
	"fmt"
	"testing"
)

func TestPrintableString_encodingRules(t *testing.T) {
	for _, input := range []any{
		"PrintableTest",
	} {
		for _, rule := range encodingRules {
			ps, err := NewPrintableString(input)
			if err != nil {
				t.Fatalf("%s failed [%s NewPrintableString]: %v", t.Name(), rule, err)
			}

			var pkt PDU
			if pkt, err = Marshal(ps, With(rule)); err != nil {
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

func TestPrintableString_codecov(t *testing.T) {
	ps, _ := NewPrintableString(`Hello`)
	ps.Tag()
	ps.Len()
	if ps.IsZero() {
		t.Fatal("Expected IsZero() to return false for a non-empty PrintableString")
	}
	ps.IsPrimitive()
	_ = ps.String()
	NewPrintableString(ps)
	NewPrintableString(string(rune(0xFFFFF)))

	badRune := uint32(0xD800)
	b := []byte{
		byte(badRune >> 24),
		byte(badRune >> 16),
		byte(badRune >> 8),
		byte(badRune),
	}
	PrintableSpec(PrintableString(b))

	for _, valid := range []struct {
		value  any
		expect string
	}{
		{
			value:  "ABCabc0123 '()+,-./:?",
			expect: "ABCabc0123 '()+,-./:?",
		},
		{
			value:  "Hello, World",
			expect: "Hello, World",
		},
		{
			value:  []byte("ABCabc0123 '()+,-./:?"),
			expect: "ABCabc0123 '()+,-./:?",
		},
	} {
		if p, err := NewPrintableString(valid.value); err != nil {
			t.Fatalf("NewPrintableString(%q) returned error: %v", valid.value, err)
		} else if p.String() != valid.expect {
			t.Fatalf("Expected PrintableString.String() = %q, got %q", valid.value, p.String())
		}
	}

	for _, bogus := range []any{
		"",        // Zero len
		12345,     // Not a string
		"ABC@DEF", // Illegal use of '@'
	} {
		if _, err := NewPrintableString(bogus); err == nil {
			t.Fatalf("%s: expected error for bogus %T (%v) input, got nil",
				t.Name(), bogus, bogus)
		}
	}

}

type customPrintable PrintableString

func (_ customPrintable) Tag() int          { return TagPrintableString }
func (_ customPrintable) String() string    { return `` }
func (_ customPrintable) IsPrimitive() bool { return true }

func TestCustomPrintableString_withControls(t *testing.T) {
	RegisterTextAlias[customPrintable](TagPrintableString, // any <X>String tag would do (except BitString)
		// dummy decoding verifier -- nil is sufficient in most cases
		func([]byte) error { return nil }, // verify decoder
		// dummy decoder -- nil is sufficient in most cases
		func(b []byte) (customPrintable, error) { return customPrintable(b), nil }, // custom decoder
		// dummy encoder -- nil is sufficient in most cases
		func(p customPrintable) ([]byte, error) { return []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}, nil }, // custom encoder
		// asn1plus built-in PrintableString specification constraint
		func(p customPrintable) error { return PrintableSpec(PrintableString(p)) },
		// user-provided constraint(s) -- provide as many as
		// desired, ordered in the most logical way. Leave
		// empty if no custom constraints are needed.
		LiftConstraint(func(o customPrintable) customPrintable { return o },
			func(o customPrintable) (err error) {
				for i := 0; i < len(o); i++ {
					if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
						err = fmt.Errorf("Constraint violation: policy prohibits digits")
						break
					}
				}
				return
			}),
	)

	var cust customPrintable = customPrintable("Hello")
	cust.Tag()
	cust.IsPrimitive()
	_ = cust.String()

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customPrintable
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func ExamplePrintableString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o PrintableString) PrintableString { return o },
		func(o PrintableString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o PrintableString) PrintableString { return o },
		func(o PrintableString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewPrintableString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewPrintableString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}

func BenchmarkPrintableStringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		PrintableString("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewPrintableString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
