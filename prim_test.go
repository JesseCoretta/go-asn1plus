package asn1plus

import "testing"

func TestPrimitive_codecov(_ *testing.T) {
	opts := Options{}
	primitiveCheckExplicitRead(1, &BERPacket{}, TLV{Class: -1, Tag: -1, Compound: false}, Options{})

	opts.SetClass(0)
	opts.SetTag(2)
	primitiveCheckExplicitRead(1, &BERPacket{}, TLV{Class: 0, Tag: 2, Compound: true}, opts)
}
