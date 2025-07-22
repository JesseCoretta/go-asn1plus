package asn1plus

import "testing"

func TestNull_encodingRules(t *testing.T) {
	for _, rule := range encodingRules {
		var null Null
		pkt, err := Marshal(null, With(rule))
		if err != nil {
			t.Errorf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			return
		}

		var null2 Null
		if err = Unmarshal(pkt, &null2); err != nil {
			t.Errorf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			return
		}

		want := "05 00"
		if got := pkt.Hex(); got != want {
			t.Errorf("%s failed [%s hex cmp.]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}
	}
}

func TestNull_codecov(t *testing.T) {
	var null Null
	null.Tag()
	null.Len()
	null.IsPrimitive()
	_ = null.String()
	errorNullLengthNonZero(1)

	nc := new(nullCodec[Null])
	nc.encodeHook = func(b Null) ([]byte, error) {
		return []byte{}, nil
	}
	nc.decodeHook = func(b []byte) (Null, error) {
		return Null{}, nil
	}
	nc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	nc.Tag()
	nc.IsPrimitive()
	_ = nc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = nc.write(tpkt, nil)
	_, _ = nc.write(bpkt, nil)
	nc.read(tpkt, TLV{}, nil)
	bpkt.data = []byte{0x1, 0x1, 0xFF, 0xFF}
	nc.read(tpkt, TLV{}, nil)
	nc.read(bpkt, TLV{}, nil)

	if f, ok := master[refTypeOf(Null{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(Null{}).(box)
	}

}

func TestNull_customType(t *testing.T) {
	type customNull Null
	RegisterNullAlias[customNull](TagNull,
		NullConstraintPhase,
		func([]byte) error { return nil },
		func(customNull) ([]byte, error) { return nil, nil },
		func([]byte) (customNull, error) { return customNull{}, nil },
		func(any) error { return nil })

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	cust := customNull{}

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out customNull
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}
