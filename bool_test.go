package asn1plus

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNewBoolean(t *testing.T) {
	var b bool
	for idx, boo := range []any{
		!b,
		&b,
		`true`,
		`TRUE`,
		byte(0xff),
		0,
		1,
	} {
		if B, err := NewBoolean(boo); err != nil {
			t.Errorf("%s[%d] failed [Boolean parse]: %v", t.Name(), idx, err)
		} else {
			B.IsPrimitive()
			B.Tag()
			B.Bool()
			B.Byte()
			_ = B.String()

			for _, rule := range encodingRules {
				var pkt Packet
				if pkt, err = Marshal(B, With(rule)); err != nil {
					t.Errorf("%s[%d] failed [%s encoding]: %v", t.Name(), idx, rule, err)
					continue
				}

				if err != nil {
					t.Errorf("%s[%d] failed [%s FullBytes()]: %v", t.Name(), idx, rule, err)
				}

				var B2 Boolean
				if err = Unmarshal(pkt, &B2); err != nil {
					t.Errorf("%s[%d] failed [%s decoding]: %v", t.Name(), idx, rule, err)
					continue
				}

				if B != B2 {
					t.Errorf("%s[%d] failed [%s Boolean string cmp.]:\n\twant: %t\n\tgot:  %t",
						t.Name(), idx, rule, B, B2)
					continue
				}
			}
		}
	}
}

func TestBoolean_codecov(t *testing.T) {
	_, _ = NewBoolean(struct{}{})
	bc := new(booleanCodec[Boolean])
	bc.encodeHook = func(b Boolean) ([]byte, error) {
		return []byte{b.Byte()}, nil
	}
	bc.decodeHook = func(b []byte) (Boolean, error) {
		return Boolean(b[0]==0xFF), nil
	}
	bc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	bc.IsPrimitive()
	_ = bc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = bc.write(tpkt, nil)
	_, _ = bc.write(bpkt, nil)
	bc.read(tpkt, TLV{}, nil)
}

type customBoolean Boolean
func (_ customBoolean) Tag() int { return TagBoolean }
func (_ customBoolean) String() string { return `` }
func (_ customBoolean) IsPrimitive() bool { return true }

func TestCustomBoolean_withControls(t *testing.T) {
	RegisterBooleanAlias[customBoolean](TagBoolean,
		func([]byte) error {
			return nil
		},
		func(customBoolean) ([]byte, error) {
			return []byte{0x1, 0x1, 0xFF}, nil
		},
		func([]byte) (customBoolean, error) {
			return customBoolean(true), nil
		},
		nil)

	var cust customBoolean = customBoolean(true)

	pkt, err := Marshal(cust, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var next customBoolean
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}
	unregisterType(reflect.TypeOf(cust))
}

func ExampleNewBoolean() {
	// accepts bool, *bool, Boolean, byte (0x00 or 0xFF),
	// or any valid strconv.ParseBool string input.
	bewl, err := NewBoolean("false")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%T was %t, ", bewl, bewl)

	bewl = Boolean(true)
	fmt.Printf("but is now %t.\n", bewl)
	// Output: asn1plus.Boolean was false, but is now true.
}

func ExampleBoolean_withConstraint() {
	constraint := LiftConstraint(func(b Boolean) Boolean { return b },
		func(b Boolean) (err error) {
			if !b.Bool() {
				err = fmt.Errorf("Constraint violation: Boolean must be true")
			}
			return
		})

	if _, err := NewBoolean("false", constraint); err != nil {
		fmt.Println(err)
		return
	}
	// Output: Constraint violation: Boolean must be true
}
