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

	buildText(
		string([]byte{0xFF}),
		0x1E,
		10,
		4,
		func(r rune, dst []byte, pos int) (bw, cu int, err error) {
			return 0, 0, nil
		},
	)

	buildText(
		"A",
		0x1E,
		10,
		4,
		func(r rune, dst []byte, pos int) (bw, cu int, err error) {
			return 0, 0, mkerr("error")
		},
	)
}
