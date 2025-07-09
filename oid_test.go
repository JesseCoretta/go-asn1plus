package asn1plus

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
)

func TestObjectIdentifier_customType(t *testing.T) {
	type CustomOID ObjectIdentifier
	RegisterOIDAlias[CustomOID](TagOID,
		ObjectIdentifierConstraintPhase,
		nil, nil, nil, nil)

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	orig, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	cust := CustomOID(orig)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out CustomOID
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	// We cheat again, since we didn't write a
	// custom OID method for this simple test.
	cast1 := ObjectIdentifier(orig)
	cast2 := ObjectIdentifier(cust)
	if !cast1.Eq(cast2) {
		t.Fatalf("%s failed [BER OID cmp.]:\n\twant: %s\n\tgot:  %s",
			t.Name(), cast1, cast2)
	}
}

func TestRelativeOID_customType(t *testing.T) {
	type CustomRelOID RelativeOID
	RegisterOIDAlias[CustomRelOID](TagOID,
		ObjectIdentifierConstraintPhase,
		nil, nil, nil, nil)

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	orig, _ := NewRelativeOID(1, 4, 1, 56521)
	cust := CustomRelOID(orig)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out CustomRelOID
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	// We cheat again, since we didn't write a
	// custom OID method for this simple test.
	cast1 := RelativeOID(orig).String()
	cast2 := RelativeOID(cust).String()
	if cast1 != cast2 {
		t.Fatalf("%s failed [BER Relative OID cmp.]:\n\twant: %s\n\tgot:  %s",
			t.Name(), cast1, cast2)
	}
}

/*
This example demonstrates the following:

  - Parsing a string-based OID, producing an [ObjectIdentifier] instance
  - BER encoding the resulting [ObjectIdentifier] instance, producing a BER [PDU] instance
  - Decoding the BER [PDU] into a new [ObjectIdentifier] instance
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

	// BER Encode ObjectIdentifier into PDU.
	// Supply an encoding rule other than BER
	// if desired.
	var pkt PDU
	if pkt, err = Marshal(oid, With(BER)); err != nil {
		fmt.Println(err)
		return
	}

	// BER Decode PDU into new ObjectIdentifier
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
		pkt, err := Marshal(my, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v\n", t.Name(), rule, err)
		}

		var my2 MySequence
		if err = Unmarshal(pkt, &my2); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v\n", t.Name(), rule, err)
		}
	}
}

func TestObjectIdentifier_codecov(_ *testing.T) {
	var o ObjectIdentifier
	o.Tag()
	o.IntSlice()
	o.IsPrimitive()
	o.Uint64Slice()

	_, _ = NewObjectIdentifier(`JERRY. HELLO.`)
	_, _ = NewObjectIdentifier(struct{}{})
	_, _ = NewObjectIdentifier(2, 999)
	_, _ = NewObjectIdentifier(1, 3, 6, 1)
	_, _ = NewObjectIdentifier(1, 3, ``, 1)
	_, _ = NewObjectIdentifier(1, -3, 6, 1)
	_, _ = NewObjectIdentifier(1, struct{}{}, 6, 1)
	_, _ = NewObjectIdentifier(ObjectIdentifier{})

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
	pkt, _ := Marshal(o)
	_ = Unmarshal(pkt, &o)

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

	oc := new(oidCodec[ObjectIdentifier])
	root := Integer{native: int64(1)}
	rootBad := Integer{native: int64(3)}
	second := Integer{native: int64(1)}
	secondBad := Integer{native: int64(9999)}

	bcdOIDRead(oc, &BERPacket{}, TLV{Compound: true}, nil)
	subs := []*big.Int{
		newBigInt(10),
		newBigInt(0).Lsh(newBigInt(1), 63), // 2^63, outside int64
	}
	objectIdentifierReadExpandFirstArcs(subs)

	objectIdentifierReadData(
		nil,
		TLV{
			Value:  []byte{0xAA, 0xBB, 0xCC},
			Length: 2,
		},
		nil,
	)

	objectIdentifierReadData(
		&BERPacket{data: []byte{0x05}},
		TLV{
			Value:  nil,
			Length: 0,
		},
		nil,
	)

	oc.IsPrimitive()
	oc.Tag()
	_ = oc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	oc.val = ObjectIdentifier{}
	_, _ = oc.write(bpkt, nil)

	oc.val = ObjectIdentifier{rootBad, second}
	_, _ = oc.write(tpkt, nil)
	_, _ = oc.write(bpkt, nil)
	oc.read(tpkt, TLV{}, nil)
	bpkt.data = []byte{0x1, 0x1, 0xFF, 0xFF}
	oc.read(tpkt, TLV{}, nil)
	oc.read(bpkt, TLV{}, nil)
	oc.val = ObjectIdentifier{root, secondBad}
	_, _ = oc.write(bpkt, nil)

	if f, ok := master[refTypeOf(ObjectIdentifier{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(ObjectIdentifier{}).(box)
	}
}

type customOID ObjectIdentifier

func (_ customOID) Tag() int          { return TagOID }
func (_ customOID) String() string    { return `` }
func (_ customOID) IsPrimitive() bool { return true }

func TestCustomOID_withControls(t *testing.T) {
	orig, _ := NewObjectIdentifier(1, 2, 3)
	var cust customOID
	cust = customOID(orig)

	RegisterOIDAlias[customOID](TagOID,
		ObjectIdentifierConstraintPhase,
		func(b []byte) (err error) { return nil },
		func(b customOID) ([]byte, error) {
			return []byte{0x6, 0x7, 0x2, 0x1, 0x2}, nil
		},
		func(b []byte) (customOID, error) {
			return cust, nil
		},
		nil)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customOID
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(&cust))
	unregisterType(refTypeOf(cust))
}

func TestRelativeOID_roundTripBER(t *testing.T) {
	// For this test, we define a RelativeOID with five arcs.
	rel, err := NewRelativeOID(1, 2, 3, 4, 5)
	if err != nil {
		t.Errorf("%s failed [new Relative OID]: %v", t.Name(), err)
		return
	}

	// Supply an encoding rule other than BER, if desired.
	var pkt PDU
	if pkt, err = Marshal(rel, With(BER)); err != nil {
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

type relOID RelativeOID

func (_ relOID) Tag() int          { return TagRelativeOID }
func (_ relOID) String() string    { return `` }
func (_ relOID) IsPrimitive() bool { return true }

func TestRelativeOID_codecov(_ *testing.T) {
	r, _ := NewRelativeOID(`33.44.55`)
	r.IsPrimitive()
	r.Tag()
	r, _ = NewRelativeOID(r)
	_, _ = NewRelativeOID(33, -1, 44)

	badArc := Integer{native: int64(-3)}

	rc := new(relOIDCodec[RelativeOID])
	rc.encodeHook = func(b RelativeOID) ([]byte, error) {
		return nil, nil
	}
	rc.decodeHook = func(b []byte) (RelativeOID, error) {
		return RelativeOID{}, nil
	}
	rc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	rc.IsPrimitive()
	rc.Tag()
	_ = rc.String()

	rc.val = RelativeOID{}
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = rc.write(bpkt, nil)

	rc.val = RelativeOID{badArc}
	_, _ = rc.write(tpkt, nil)
	_, _ = rc.write(bpkt, nil)
	rc.read(tpkt, TLV{}, nil)
	rc.read(bpkt, TLV{}, nil)

	bpkt.data = []byte{0x1, 0x1, 0xFF, 0xFF}
	rc.read(tpkt, TLV{}, nil)
	rc.read(bpkt, TLV{}, nil)

	if f, ok := master[refTypeOf(RelativeOID{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(RelativeOID{}).(box)
	}

	bcdRelOIDRead(
		rc,
		&BERPacket{data: []byte{
			0x0D, 0x02,
			0x81, 0x22,
		}},
		TLV{
			Class:    ClassUniversal,
			Tag:      TagRelativeOID,
			Compound: true,
			Length:   2,
			Value:    []byte{0x81, 0x22},
		},
		nil,
	)

	_ = bcdRelOIDRead(
		rc,
		&BERPacket{data: []byte{}},
		TLV{
			Class:    ClassUniversal,
			Tag:      TagRelativeOID,
			Compound: false,
			Value:    []byte{0x81, 0x22, 0x33},
			Length:   2,
		},
		nil,
	)

	_ = bcdRelOIDRead(
		rc,
		&BERPacket{data: []byte{
			0x0D, 0x01, 0x2A,
		}},
		TLV{
			Class:    ClassUniversal,
			Tag:      TagRelativeOID,
			Compound: false,
			Value:    nil,
			Length:   0,
		},
		nil,
	)

	relativeOIDReadArcs([]byte{0x81})
	relativeOIDReadArcs(append(bytes.Repeat([]byte{0x81}, 10), 0x00))
	relativeOIDReadArcs([]byte{})

	bcdRelOIDWrite(
		&relOIDCodec[RelativeOID]{
			tag: TagRelativeOID,
			val: RelativeOID{},
		},
		&BERPacket{data: []byte{}},
		nil,
	)

	bcdRelOIDRead(
		&relOIDCodec[RelativeOID]{
			tag: TagRelativeOID,
		},
		&BERPacket{data: []byte{}},
		TLV{
			Class:    ClassUniversal,
			Tag:      TagRelativeOID,
			Compound: true, // forces the getTLV call
			Length:   0,
			Value:    nil, // so getTLV(pkt,…) sees no bytes and returns an error
		},
		nil,
	)

	bcdRelOIDWrite(
		&relOIDCodec[RelativeOID]{
			tag: TagRelativeOID,
			val: RelativeOID{
				Integer{native: -1},
			},
		},
		&BERPacket{data: []byte{}},
		nil,
	)
}

func TestCustomRelativeOID_withControls(t *testing.T) {
	orig, _ := NewRelativeOID(1, 2, 3)
	var cust relOID
	cust = relOID(orig)

	RegisterRelativeOIDAlias[relOID](TagRelativeOID,
		RelativeOIDConstraintPhase,
		func(b []byte) (err error) { return nil },
		func(b relOID) ([]byte, error) {
			return []byte{0x6, 0x7, 0x2, 0x1, 0x2}, nil
		},
		func(b []byte) (relOID, error) {
			return cust, nil
		},
		nil)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next relOID
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(&cust))
	unregisterType(refTypeOf(cust))
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

func BenchmarkObjectIdentifierConstructor(b *testing.B) {
	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	for _, value := range []any{
		"1.3.6.1.4.1.56521",
		oid,
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewObjectIdentifier(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkRelativeOIDConstructor(b *testing.B) {
	for _, value := range [][]any{
		{"4.1.56521"},
		{4, 1, 56521},
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewRelativeOID(value...); err != nil {
				b.Fatal(err)
			}
		}
	}
}
