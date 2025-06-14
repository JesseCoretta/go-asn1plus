package asn1plus

import "testing"

func TestEmbeddedPDV_SyntaxesEncodingRules(t *testing.T) {
	abs, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	txf, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)

	syntaxes := Syntaxes{
		Abstract: abs,
		Transfer: txf,
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(syntaxes, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		nsyn := Syntaxes{}
		if err := Unmarshal(pkt, &nsyn); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}
	}
}

func TestEmbeddedPDV_encodingRulesChoiceSyntaxes(t *testing.T) {
	abstract, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	transfer, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)
	syntaxes := Syntaxes{abstract, transfer}

	tag := 0
	choice := Choice{Value: &syntaxes, Tag: &tag}

	pdv := EmbeddedPDV{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	hexes := map[EncodingRule]string{
		BER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		want := hexes[rule]
		if got := pkt.Hex(); got != want {
			t.Fatalf("%s failed [%s encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		if newPDV.Identification.IsZero() {
			t.Fatalf("Missing identification choice after decoding")
		}

		switch id := newPDV.Identification.Value.(type) {
		case Syntaxes:
			if id.Abstract.String() != `2.1.2.1.2.1.2.1` ||
				id.Transfer.String() != `2.0.2.0.2.0.2.0` {
				t.Fatalf("%s failed: expected Syntaxes{	Abstract: 2.1.2.1.2.1.2.1 Transfer: 2.0.2.0.2.0.2.0 }, got %#v",
					t.Name(), id)
			}
		default:
			t.Fatalf("Unexpected alternative type in identification: got %T", id)
		}

		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("DataValueDescriptor mismatch")
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("DataValue mismatch")
		}
	}
}

func TestExternal_encodingRulesChoiceSyntaxes(t *testing.T) {
	abstract, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	transfer, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)
	syntaxes := Syntaxes{abstract, transfer}

	tag := 0
	choice := Choice{Value: &syntaxes, Tag: &tag}

	pdv := External{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	hexes := map[EncodingRule]string{
		BER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		want := hexes[rule]
		if got := pkt.Hex(); got != want {
			t.Fatalf("%s failed [%s encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		if newPDV.Identification.IsZero() {
			t.Fatalf("Missing identification choice after decoding")
		}

		switch id := newPDV.Identification.Value.(type) {
		case Syntaxes:
			if id.Abstract.String() != `2.1.2.1.2.1.2.1` ||
				id.Transfer.String() != `2.0.2.0.2.0.2.0` {
				t.Fatalf("%s failed: expected Syntaxes{ Abstract: 2.1.2.1.2.1.2.1 Transfer: 2.0.2.0.2.0.2.0 }, got %#v",
					t.Name(), id)
			}
		default:
			t.Fatalf("Unexpected alternative type in identification: got %T", id)
		}

		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("DataValueDescriptor mismatch")
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("DataValue mismatch")
		}
	}
}

func TestEmbeddedPDV_encodingRulesChoiceOID(t *testing.T) {
	oid, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)

	choice := Choice{Value: &oid}
	choice.SetTag(4) // choice [4]

	pdv := EmbeddedPDV{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		t.Logf("%s PKT Hex: %s\n", rule, pkt.Hex())

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		// Now "unpack" the decoded identification field.
		if newPDV.Identification.IsZero() {
			t.Fatalf("%s failed [%s field check]: Missing identification choice after decoding",
				t.Name(), rule)
		}

		switch id := newPDV.Identification.Value.(type) {
		case ObjectIdentifier:
			// Compare the decoded OID with our original.
			if !id.Eq(oid) {
				t.Fatalf("%s failed [%s OID cmp.]: Decoding mismatch in identification: got %v; want %v",
					t.Name(), rule, id, oid)
			}
		default:
			t.Fatalf("%s failed [%s OID mismatch]: Unexpected alternative type in identification: got %T",
				t.Name(), rule, id)
		}

		// You can also check DataValueDescriptor and DataValue.
		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("%s failed [%s DataValueDescriptor mismatch]: want test, got %v",
				t.Name(), rule, newPDV.DataValueDescriptor)
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("%s failed [%s DataValue mismatch]: want blarg, got %v",
				t.Name(), rule, newPDV.DataValue)
		}
	}
}

func TestEmbeddedPDV_codecov(_ *testing.T) {
	var pdv EmbeddedPDV
	pdv.Tag()
	var ext External
	ext.Tag()
}
