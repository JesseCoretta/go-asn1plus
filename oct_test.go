package asn1plus

import (
	"fmt"
	"testing"
)

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

	oc.IsPrimitive()
	oc.Tag()
	_ = oc.String()
	tpkt := &testPacket{}
	cpkt := &CERPacket{}
	_, _ = oc.write(tpkt, nil)
	_, _ = oc.write(cpkt, nil)
	oc.read(tpkt, TLV{}, nil)
	cerSegmentedOctetStringWrite(oc, cpkt, nil)
	cpkt.offset = 100
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
	cpkt.data = nil
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
	cpkt.data = []byte{0x00}
	cerSegmentedOctetStringRead(oc, cpkt, TLV{}, nil)
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
			var pkt Packet
			if pkt, err = Marshal(od, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			}

			// Decode our Packet into a new OctetString instance
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
	digitConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

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

func ExampleOctetString_viaGoStringWithTaggedConstraint() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// Create a single constraint group and register it
	// as a tagged function. We can put as many constraint
	// functions in a group as we please.
	RegisterTaggedConstraintGroup("octetStringConstraints", ConstraintGroup[OctetString]{
		digitConstraint,
		caseConstraint,
	})

	var options Options = Options{
		Identifier:  "octet",
		Constraints: []string{`octetStringConstraints`},
	}

	pkt, err := Marshal(`test48`,
		With(DER, options))

	// We violated to the "no digits" policy.
	if err != nil {
		fmt.Println(err)
	}

	// Lets try again
	pkt, err = Marshal(`test`,
		With(DER, options))

	// We passed the "no digits" policy, but violated
	// the "no lower case" policy.
	if err != nil {
		fmt.Println(err)
	}

	pkt, err = Marshal(`TEST`,
		With(DER, options))

	// Third time's a charm?
	if err != nil {
		fmt.Println(err)
		return
	}

	// We passed all constraints.

	fmt.Printf("Encoded value: %s\n", pkt.Hex())

	var out string
	if err = Unmarshal(pkt, &out, With(options)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded value: %s", out)
	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
	// Encoded value: 04 04 54455354
	// Decoded value: TEST
}

func TestPacket_LargeOctetStringCER(t *testing.T) {
	var large OctetString = OctetString(strrpt("X", 2001)) // X*2001 times

	pkt, err := Marshal(large, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var alsoLarge OctetString
	if err = Unmarshal(pkt, &alsoLarge); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}

	want := large.Len()
	got := alsoLarge.Len()
	if want != got {
		t.Fatalf("%s failed [CER large OctetString size cmp.]:\n\twant: %d bytes\n\tgot:  %d bytes",
			t.Name(), want, got)
	}
}
