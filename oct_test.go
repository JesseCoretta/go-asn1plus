package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewOctetString_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), errorNoPanic)
		}
	}()
	_ = MustNewOctetString(struct{}{})
}

func TestOctetString_codecov(_ *testing.T) {
	o, _ := NewOctetString(`test`)
	o.Tag()
	_, _ = Marshal(o)
	//o.read(pkt, TLV{typ: DER, Class: 0, Tag: o.Tag(), Length: 1000}, nil)
	_, _ = NewOctetString(nil)
	_, _ = NewOctetString(struct{}{})
	NewOctetString(string(rune(0xFFFFF)))

	oc := new(textCodec[OctetString])
	oc.encodeHook = func(b OctetString) ([]byte, error) {
		return []byte{0x4, 0x4, 0xc1, 0x3, 0x12, 0xd7}, nil
	}
	oc.decodeHook = func(b []byte) (OctetString, error) {
		return OctetString("test"), nil
	}
	oc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}

	if f, ok := master[refTypeOf(OctetString{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(OctetString{}).(box)
	}

	OctetSpec(``)
	OctetSpec(`test`)
	OctetSpec([]byte(`test`))
	OctetSpec(struct{}{})

	oc.IsPrimitive()
	oc.Tag()
	_ = oc.String()
	tpkt := &testPacket{}
	_, _ = oc.write(tpkt, nil)
	oc.read(tpkt, TLV{}, nil)
}

func TestOctetString_encodingRules(t *testing.T) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		OctetString("objectName"),
	} {
		for _, rule := range encodingRules {
			// Parse our ASN.1 OCTET STRING
			od, err := NewOctetString(value)
			if err != nil {
				t.Fatalf("%s failed [New OctetString]: %v", t.Name(), err)
			}
			od.IsPrimitive()
			_ = od.String()
			od.Tag()
			od.Len()
			od.IsZero()

			// encode our OctetString instance
			var pkt PDU
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our PDU into a new OctetString instance
			var other OctetString
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

func ExampleOctetString_withConstraints() {
	// Prohibit use of any digit characters
	digitConstraint := func(x any) (err error) {
		o, _ := x.(OctetString)
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
		o, _ := x.(OctetString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	// First try trips on a digit violation, so caseConstraint is never reached.
	_, err := NewOctetString(`A0B876EFFFF0`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Second try honors the digit policy, but fails on case folding.
	_, err = NewOctetString(`ABACFFfBECD`, digitConstraint, caseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
}

func BenchmarkOctetStringConstructor(b *testing.B) {
	for _, value := range []any{
		"objectName",
		[]byte("objectName"),
		OctetString("objectName"),
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewOctetString(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
