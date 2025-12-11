package asn1plus

import "testing"

func TestMustMarshalRoundtrip(t *testing.T) {
	x := MustNewPrintableString("testing123")
	pkt := MustMarshal(x)
	var dest PrintableString
	MustUnmarshal(pkt, &dest)
}
