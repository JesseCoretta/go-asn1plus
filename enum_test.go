package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewEnumerated_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), errorNoPanic)
		}
	}()
	_ = MustNewEnumerated(struct{}{})
}

func TestCustomEnumerated_withControls(t *testing.T) {
	orig, _ := NewEnumerated(123456, func(any) error {
		return nil
	})
	var cust enum = enum(orig) // cheat

	RegisterEnumeratedAlias[enum](TagEnum,
		EnumeratedConstraintPhase,
		func([]byte) error {
			return nil
		},
		func(enum) ([]byte, error) {
			return []byte{0x9, 0x5, 0xc1, 0x3, 0x12, 0xd6, 0x87}, nil
		},
		func([]byte) (enum, error) {
			return cust, nil
		},
		func(any) error { return nil },
		func(any) error { return nil })

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next enum
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func ExampleEnumerated_roundTripBER() {
	var e Enumerated = 3
	pkt, err := Marshal(e, With(BER)) // or CER, DER, et al.
	if err != nil {
		fmt.Println(err)
		return
	}

	if err = Unmarshal(pkt, &e); err == nil {
		enums := Enumeration{
			Enumerated(1): "one",
			Enumerated(2): "two",
			Enumerated(3): "three",
			Enumerated(4): "four",
			Enumerated(5): "five",
		}
		fmt.Printf("Known Enumerated: %s (%d)\n", enums.Name(e), e)
	}

	// Output: Known Enumerated: three (3)
}

type enum int

func (_ enum) Tag() int          { return TagEnum }
func (_ enum) String() string    { return `` }
func (_ enum) IsPrimitive() bool { return true }

func TestEnumerated_codecov(t *testing.T) {

	RegisterEnumeratedAlias[enum](TagEnum,
		EnumeratedConstraintPhase,
		func(b []byte) error { return nil },
		func(b enum) ([]byte, error) {
			return []byte{0x00}, nil
		},
		func(b []byte) (enum, error) {
			return enum(3), nil
		},
		nil)

	_, _ = NewEnumerated(struct{}{})
	_, _ = NewEnumerated(Enumerated(3))
	e, _ := NewEnumerated(3)
	e.Tag()
	_ = e.String()
	e.IsPrimitive()
	opts := &Options{}
	opts.SetTag(4)

	three, _ := NewInteger(3)
	ec := new(enumeratedCodec[Enumerated])
	ec.base = new(integerCodec[Integer])
	ec.base.encodeHook = func(b Integer) ([]byte, error) {
		return []byte{0x00}, nil
	}
	ec.base.decodeHook = func(b []byte) (Integer, error) {
		return three, nil
	}
	ec.base.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	ec.IsPrimitive()
	ec.Tag()
	_ = ec.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = ec.write(tpkt, nil)
	_, _ = ec.write(bpkt, nil)
	ec.read(tpkt, TLV{}, nil)
	bpkt.data = []byte{0x1, 0x1, 0xFF, 0xFF}
	ec.read(tpkt, TLV{}, nil)
	ec.read(bpkt, TLV{}, nil)

	if f, ok := master[refTypeOf(Enumerated(3))]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(Enumerated(3)).(box)
	}

	for _, rule := range encodingRules {
		var pkt PDU
		var err error
		if pkt, err = Marshal(e, With(rule)); err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var e2 Enumerated
		if err = Unmarshal(pkt, &e2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
		_ = e2.String()

		if int(e) != int(e2) {
			t.Fatalf("%s failed [%s Enumerated integer cmp.]:\n\twant: %d\n\tgot:  %d",
				t.Name(), rule, e, e2)
		}
	}
}

func BenchmarkEnumeratedConstructor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewEnumerated(56); err != nil {
			b.Fatal(err)
		}
	}
}
