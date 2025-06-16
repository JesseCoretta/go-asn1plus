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

func TestEmbeddedPDV_codecov(_ *testing.T) {
	var pdv EmbeddedPDV
	pdv.Tag()
	var ext External
	ext.Tag()
}
