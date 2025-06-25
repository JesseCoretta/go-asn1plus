package asn1plus

import "testing"

func TestPrimitive_codecov(_ *testing.T) {
	primitiveCheckExplicitRead(1, &BERPacket{}, TLV{Class: -1, Tag: -1, Compound: false}, &Options{})

	opts := &Options{}
	opts.SetClass(0)
	opts.SetTag(2)
	primitiveCheckExplicitRead(1, &BERPacket{}, TLV{Class: 0, Tag: 2, Compound: true}, opts)
	tag := 3
	primitiveCheckReadOverride(1, &BERPacket{}, TLV{Class: 0, Tag: 2, Compound: false}, &Options{Explicit: true, tag: &tag})
	primitiveCheckReadOverride(1, &BERPacket{}, TLV{Class: 1, Tag: 2, Compound: false}, nil)
	primitiveCheckReadOverride(1, &BERPacket{}, TLV{Class: 0, Tag: 1, Compound: false}, nil)
	primitiveCheckRead(0, &DERPacket{}, TLV{}, &Options{Indefinite: true})
	class := 0
	primitiveCheckExplicitRead(3,
		&BERPacket{data: []byte{
			0x0c, 0x16, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
			0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
			0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67}},
		TLV{Class: 0, Tag: 3, Compound: true},
		&Options{class: &class, tag: &tag})
	primitiveCheckImplicitRead(3, &BERPacket{}, TLV{Tag: 8}, &Options{class: &class, tag: &tag})
	primitiveCheckImplicitRead(3, &BERPacket{}, TLV{Tag: 8}, &Options{})
	primitiveCheckRead(1,
		&BERPacket{data: []byte{
			0x0c, 0x80, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
			0x73, 0x20, 0x61, 0x20, 0x55, 0x54, 0x46, 0x2d,
			0x38, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
			0x00, 0x00}},
		TLV{Class: 0, Tag: 2, Compound: false}, &Options{tag: &tag})
}
