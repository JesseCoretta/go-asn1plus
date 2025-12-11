package asn1plus

import "testing"

func TestMustMarshalRoundtrip(t *testing.T) {
	// Simply for code coverage
	var dest PrintableString
	MustUnmarshal(MustMarshal(MustNewPrintableString("testing123")), &dest)
}
