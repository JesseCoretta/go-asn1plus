//go:build asn1_no_cer

package asn1plus

func cerSegmentedBitStringRead[T any](
	_ *bitStringCodec[T],
	_ PDU,
	_ TLV,
	_ *Options,
) (err error) {
	err = errorRuleNotImplemented
	return
}

func cerSegmentedBitStringWrite[T any](
	_ *bitStringCodec[T],
	_ PDU,
	_ *Options,
) (_ int, err error) {
	err = errorRuleNotImplemented
	return
}

func cerSegmentedOctetStringRead[T TextLike](
	_ *textCodec[T],
	_ PDU,
	_ TLV,
	_ *Options,
) (err error) {
	err = errorRuleNotImplemented
	return
}

func cerSegmentedOctetStringWrite[T TextLike](
	_ *textCodec[T],
	_ PDU,
	_ *Options,
) (_ int, err error) {
	err = errorRuleNotImplemented
	return
}
