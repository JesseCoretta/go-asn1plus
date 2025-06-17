package asn1plus

import (
	"fmt"
	"testing"
)

/*
This example demonstrates the following:

  - Parsing a string-based OID, producing an [ObjectIdentifier] instance
  - BER encoding the resulting [ObjectIdentifier] instance, producing a BER [Packet] instance
  - Decoding the BER [Packet] into a new [ObjectIdentifier] instance
  - Comparing the string representation between the two [ObjectIdentifier] instances to verify they match
*/
func ExampleObjectIdentifier_roundTripBER() {
	// Parse
	strOID := `1.3.6.1.4.1.56521`
	oid, err := NewObjectIdentifier(strOID)
	if err != nil {
		fmt.Println(err)
		return
	}

	// BER Encode ObjectIdentifier into Packet
	var pkt Packet
	if pkt, err = Marshal(oid, WithEncoding(BER)); err != nil {
		fmt.Println(err)
		return
	}

	// BER Decode Packet into new ObjectIdentifier
	var oid2 ObjectIdentifier
	if err = Unmarshal(pkt, &oid2); err != nil {
		fmt.Println(err)
		return
	}

	// Verify string representation
	fmt.Printf("OIDs match: %t: %s\n", oid.String() == oid2.String(), oid)
	// Output: OIDs match: true: 1.3.6.1.4.1.56521
}

func TestObjectIdentifier_InStruct(t *testing.T) {
	type MySequence struct {
		OID ObjectIdentifier `asn1:"explicit,tag:0"`
	}

	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 1234567)
	my := MySequence{OID: oid}

	for _, rule := range encodingRules {
		pkt, err := Marshal(my, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v\n", t.Name(), rule, err)
		}

		var my2 MySequence
		if err = Unmarshal(pkt, &my2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v\n", t.Name(), rule, err)
		}
	}
}

/*
This example demonstrates the following:

  - Parsing a string-based OID, producing an [ObjectIdentifier] instance
  - DER encoding the resulting [ObjectIdentifier] instance, producing a DER [Packet] instance
  - Decoding the DER [Packet] into a new [ObjectIdentifier] instance
  - Comparing the string representation between the two [ObjectIdentifier] instances to verify they match
*/
func ExampleObjectIdentifier_roundTripDER() {
	// Parse
	strOID := `1.3.6.1.4.1.56521`
	oid, err := NewObjectIdentifier(strOID)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER Encode ObjectIdentifier into Packet
	var pkt Packet
	if pkt, err = Marshal(oid, WithEncoding(DER)); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("HEX: %s\n", pkt.Hex())

	// DER Decode Packet into new ObjectIdentifier
	var oid2 ObjectIdentifier
	if err = Unmarshal(pkt, &oid2); err != nil {
		fmt.Println(err)
		return
	}

	// Verify string representation
	fmt.Printf("OIDs match: %t: %s\n", oid.String() == oid2.String(), oid)
	// Output:
	// HEX: 06 08 2B0601040183B949
	// OIDs match: true: 1.3.6.1.4.1.56521
}

func TestObjectIdentifier_codecov(_ *testing.T) {
	var o ObjectIdentifier
	o.Tag()
	o.IntSlice()
	o.IsPrimitive()
	o.Uint64Slice()
	o.write(nil, &Options{})

	_, _ = NewObjectIdentifier(`JERRY. HELLO.`)
	_, _ = NewObjectIdentifier(struct{}{})
	_, _ = NewObjectIdentifier(2, 999)
	_, _ = NewObjectIdentifier(1, 3, 6, 1)
	_, _ = NewObjectIdentifier(1, 3, ``, 1)
	_, _ = NewObjectIdentifier(1, -3, 6, 1)
	_, _ = NewObjectIdentifier(1, struct{}{}, 6, 1)

	nf, _ := NewInteger(1)
	o = append(o, nf)
	o.Index(0)
	o.Index(5550)
	o.Index(-1)
	o.IntSlice()
	o.Uint64Slice()

	o, _ = NewObjectIdentifier(`1.3.6.1.4.1.56521`)
	o, _ = NewObjectIdentifier(o)
	o.Valid()
	o.IntSlice()
	o.Uint64Slice()
	o.Index(1)
	der, _ := Marshal(o)
	_ = Unmarshal(der, &o)
	o.read(nil, TLV{}, &Options{})
	o.read(&DERPacket{}, TLV{}, &Options{})
	o.read(&DERPacket{data: []byte{0x05, 0x01, 0x01}}, TLV{}, &Options{})
	o.read(&DERPacket{data: []byte{0x05, 0x1f, 0x01}}, TLV{}, &Options{})
	o.write(der, &Options{})

	isNumericOID(`-4`)
	isNumericOID(`4`)
	isNumericOID(`1`)
	isNumericOID(`1.3`)
	isNumericOID(`1.73248932789473247392`)
	isNumericOID(`3.3`)
	isNumericOID(`1.999`)
	isNumericOID(`1.3..3`)
	isNumericOID(`1.3.3.`)
	isNumericOID(`1.3.AA`)
}

func TestRelativeOID_roundTripBER(t *testing.T) {
	// For this test, we define a RelativeOID with five arcs.
	rel, err := NewRelativeOID(1, 2, 3, 4, 5)
	if err != nil {
		t.Errorf("%s failed [new Relative OID]: %v", t.Name(), err)
		return
	}

	var pkt Packet
	if pkt, err = Marshal(rel, WithEncoding(BER)); err != nil {
		t.Errorf("%s failed [DER encode]: %v", t.Name(), err)
		return
	}

	var rel2 RelativeOID
	if err = Unmarshal(pkt, &rel2); err != nil {
		t.Errorf("%s failed [DER decode]: %v", t.Name(), err)
		return
	}

	if rel.String() != rel2.String() {
		t.Errorf("%s failed [Relative OID string cmp.]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rel, rel2)
		return
	}

	rel.Tag()
	rel.IsZero()
	rel.Len()
}

func TestRelativeOID_roundTripDER(t *testing.T) {
	// For this test, we define a RelativeOID with five arcs.
	rel, err := NewRelativeOID(1, 2, 3, 4, 5)
	if err != nil {
		t.Errorf("%s failed [new Relative OID]: %v", t.Name(), err)
		return
	}

	var pkt Packet
	if pkt, err = Marshal(rel, WithEncoding(DER)); err != nil {
		t.Errorf("%s failed [DER encode]: %v", t.Name(), err)
		return
	}

	var rel2 RelativeOID
	if err = Unmarshal(pkt, &rel2); err != nil {
		t.Errorf("%s failed [DER decode]: %v", t.Name(), err)
		return
	}

	if rel.String() != rel2.String() {
		t.Errorf("%s failed [Relative OID string cmp.]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rel, rel2)
		return
	}

	rel.Tag()
	rel.IsZero()
	rel.Len()
}

func ExampleRelativeOID_Absolute() {
	// this is our base OID (1.3.6.1.4.1.56521)
	oid, err := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a new relative OID (389). Feel free
	// to add as many other arcs as desired, e.g.:
	// 389, 11, 44 for "389.11.44".
	var rel RelativeOID
	if rel, err = NewRelativeOID(389); err != nil {
		fmt.Println(err)
		return
	}

	// Create a new absolute OID (oid + . + rel)
	fmt.Println(rel.Absolute(oid))
	// Output: 1.3.6.1.4.1.56521.389
}

func TestRelativeOID_codecov(_ *testing.T) {
	r, _ := NewRelativeOID(`33.44.55`)
	r.IsPrimitive()
	r.Tag()
	r, _ = NewRelativeOID(r)
}

func ExampleNewObjectIdentifier_withConstraint() {
	mustBeISOOrg := func(oid ObjectIdentifier) (err error) {
		iso, _ := NewInteger(1)
		org, _ := NewInteger(3)
		if !(oid[0].Eq(iso) && oid[1].Eq(org)) {
			err = fmt.Errorf("Constraint violation: OID must be an ISO Org OID (must begin with 1.3)")
		}
		return
	}

	iSOConstraint := LiftConstraint(func(oid ObjectIdentifier) ObjectIdentifier {
		return oid
	}, mustBeISOOrg)

	_, err := NewObjectIdentifier(2, 1, iSOConstraint)
	if err != nil {
		fmt.Println(err)
	}
	// Output: Constraint violation: OID must be an ISO Org OID (must begin with 1.3)
}

func ExampleObjectIdentifier_viaGoString() {
	opts := Options{Identifier: "oid"}
	pkt, err := Marshal("1.3.6.1.4.1.56521",
		WithEncoding(BER),
		WithOptions(opts),
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Jesse's encoded OID: %s\n", pkt.Hex())

	var oid string
	if err = Unmarshal(pkt, &oid, WithOptions(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Jesse's decoded OID: %s", oid)
	// Output:
	// Jesse's encoded OID: 06 08 2B0601040183B949
	// Jesse's decoded OID: 1.3.6.1.4.1.56521
}

func ExampleObjectIdentifier_sequenceWithStringOID() {
	type MySequence struct {
		Name string `asn1:"descriptor"`
		OID  string `asn1:"oid"`
	}

	mine := MySequence{"Jesse Coretta", "1.3.6.1.4.1.56521"}

	pkt, err := Marshal(mine, WithEncoding(BER))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Encoded sequence: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded sequence: %s, %s", mine2.Name, mine2.OID)
	// Output:
	// Encoded sequence: 30 19 070D4A6573736520436F726574746106082B0601040183B949
	// Decoded sequence: Jesse Coretta, 1.3.6.1.4.1.56521
}
