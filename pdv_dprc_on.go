//go:build !asn1_no_dprc

package asn1plus

/*
Deprecated: External implements the ASN.1 EXTERNAL type (tag 8).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems. Use [EmbeddedPDV] instead.
*/
type External struct {
	Identification      Choice
	DataValueDescriptor ObjectDescriptor `asn1:"optional"`
	DataValue           OctetString
}

/*
Tag returns the integer constant [TagExternal].
*/
func (r External) Tag() int { return TagExternal }

func externalSpecial() *Options {
	opts := implicitOptions()
	opts.SetClass(0)
	opts.SetTag(TagExternal)
	return opts
}

func embeddedPDVOrExternalSpecial(v any) (o *Options, ok bool) {
	switch v.(type) {
	case EmbeddedPDV, *EmbeddedPDV:
		o = embeddedPDVSpecial()
		ok = true
	case External, *External:
		o = externalSpecial()
		ok = true
	}

	return
}
