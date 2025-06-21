package asn1plus

import "testing"

func TestText_codecov(t *testing.T) {
	_, _ = NewOctetString(struct{}{})
	tc := new(textCodec[OctetString])
	tc.encodeHook = func(b OctetString) ([]byte, error) {
		return []byte(b), nil
	}
	tc.decodeHook = func(b []byte) (OctetString, error) {
		return OctetString("HELLO?"), nil
	}
	tc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	tc.IsPrimitive()
	tc.Tag()
	_ = tc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = tc.write(tpkt, nil)
	_, _ = tc.write(bpkt, nil)
	tc.read(tpkt, TLV{}, nil)

	if f, ok := master[refTypeOf(OctetString(`test`))]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(OctetString(``)).(box)
	}

}

type customText PrintableString

func (_ customText) Tag() int          { return TagPrintableString }
func (_ customText) String() string    { return `` }
func (_ customText) IsPrimitive() bool { return true }

func TestCustomText_withControls(t *testing.T) {
	RegisterTextAlias[customText](TagPrintableString, // any <X>String tag would do (except BitString)
		func([]byte) error { return nil },                                       // verify decoder
		func(b []byte) (customText, error) { return customText(b), nil },        // custom decoder
		func(customText) ([]byte, error) { return []byte{0x1, 0x1, 0xFF}, nil }, // custom encoder
		nil, // spec constraint
	)

	var cust customText = customText("Hello!")

	pkt, err := Marshal(cust, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var next customText
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}
