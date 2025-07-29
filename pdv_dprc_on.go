//go:build !asn1_no_dprc

package asn1plus

/*
Deprecated: External implements the ASN.1 EXTERNAL type (tag 8).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems. Use [EmbeddedPDV] instead.
*/
type External struct {
	Identification      Choice            `asn1:"choices:identification"`
	DataValueDescriptor *ObjectDescriptor `asn1:"optional,absent"`
	DataValue           OctetString
	Extensions          []TLV `asn1:"..."`
}

/*
Tag returns the integer constant [TagExternal].
*/
func (r External) Tag() int { return TagExternal }

func init() {
	extOpts := &Options{}
	extOpts.SetTag(TagExternal).SetClass(0)
	RegisterOverrideOptions(External{}, extOpts)
}
