//go:build !asn1_no_dprc

package asn1plus

import "testing"

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
		CER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, With(rule))
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

func TestExternal_codecov(_ *testing.T) {
	var ext External
	ext.Tag()
}
