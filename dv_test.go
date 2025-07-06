package asn1plus

import "testing"

func TestDefaultValue_codecov(_ *testing.T) {
	RegisterDefaultValue("", nil)
	RegisterDefaultValue("blarg", nil)
	DefaultValues()
	lookupDefaultValue("bogus")
}

func TestDefaultValue_Primitive(t *testing.T) {
	def := PrintableString("this is the default")
	RegisterDefaultValue("myPS", def)

	type MySequence struct {
		Field1 OctetString
		Field2 PrintableString `asn1:"default::myPS"`
	}

	oct := OctetString("test")
	my := MySequence{oct, def}

	pkt, err := Marshal(my)
	if err != nil {
		t.Fatalf("%s failed [[1] BER encoding]: %v", t.Name(), err)
	}

	t.Logf("[1] BER encoding: %s\n", pkt.Hex())

	var dest MySequence
	if err = Unmarshal(pkt, &dest); err != nil {
		t.Fatalf("%s failed [[1] BER decoding]: %v", t.Name(), err)
	}

	t.Logf("[1] Unmarshaled: %#v\n", dest)

	// Try it a second time, this time set a non-default ps val
	my.Field2 = PrintableString("not a default")

	if pkt, err = Marshal(my); err != nil {
		t.Fatalf("%s failed [[2] BER encoding]: %v", t.Name(), err)
	}

	t.Logf("[2] BER encoding: %s\n", pkt.Hex())

	var dest2 MySequence
	if err = Unmarshal(pkt, &dest2); err != nil {
		t.Fatalf("%s failed [[2] BER decoding]: %v", t.Name(), err)
	}
	UnregisterDefaultValue("myPS")

	t.Logf("[2] Unmarshaled: %#v\n", dest2)
}

func TestDefaultValue_Sequence(t *testing.T) {
	type MyOtherSequence struct {
		FieldX OctetString
	}
	oth := MyOtherSequence{OctetString("deep default")}

	RegisterDefaultValue("myOther", oth)

	type MySequence struct {
		Field1 OctetString
		Field2 MyOtherSequence `asn1:"default::myOther"`
	}

	oct := OctetString("test")
	my := MySequence{oct, oth}

	pkt, err := Marshal(my)
	if err != nil {
		t.Fatalf("%s failed [[1] BER encoding]: %v", t.Name(), err)
	}

	t.Logf("[1] BER encoding: %s\n", pkt.Hex())

	var dest MySequence
	if err = Unmarshal(pkt, &dest); err != nil {
		t.Fatalf("%s failed [[1] BER decoding]: %v", t.Name(), err)
	}

	t.Logf("[1] Unmarshaled: %#v\n", dest)

	// Try it a second time, this time set a non-default ps val
	my.Field2 = MyOtherSequence{OctetString("super unique value")}

	if pkt, err = Marshal(my); err != nil {
		t.Fatalf("%s failed [[2] BER encoding]: %v", t.Name(), err)
	}

	t.Logf("[2] BER encoding: %s\n", pkt.Hex())

	var dest2 MySequence
	if err = Unmarshal(pkt, &dest2); err != nil {
		t.Fatalf("%s failed [[2] BER decoding]: %v", t.Name(), err)
	}
	UnregisterDefaultValue("myOth")

	t.Logf("[2] Unmarshaled: %#v\n", dest2)
}
