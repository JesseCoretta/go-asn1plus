//go:build asn1_no_dprc

package asn1plus

func externalSpecial() *Options { return nil }

func embeddedPDVOrExternalSpecial(v any) (o *Options, ok bool) {
	switch v.(type) {
	case EmbeddedPDV, *EmbeddedPDV:
		o = embeddedPDVSpecial()
		ok = true
	}

	return
}
