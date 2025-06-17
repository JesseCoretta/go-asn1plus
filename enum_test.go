package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleEnumerated_roundTripBER() {
	var e Enumerated = 3
	pkt, err := Marshal(e, WithEncoding(BER))
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

func ExampleEnumerated_roundTripDER() {
	var e Enumerated = 3
	pkt, err := Marshal(e, WithEncoding(DER))
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

func TestEnumerated_codecov(t *testing.T) {
	_, _ = NewEnumerated(struct{}{})
	_, _ = NewEnumerated(Enumerated(3))
	e, _ := NewEnumerated(3)
	e.write(&DERPacket{data: []byte{0x00}}, &Options{})
	e.Tag()
	e.Int()
	e.IsPrimitive()
	opts := &Options{}
	opts.SetTag(4)
	e.readBER(&BERPacket{data: []byte{0x00}}, TLV{}, opts)

	for _, rule := range encodingRules {
		var pkt Packet
		var err error
		if pkt, err = Marshal(e, WithEncoding(rule)); err != nil {
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
