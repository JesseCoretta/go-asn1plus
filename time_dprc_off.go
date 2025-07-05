//go:build asn1_no_dprc

package asn1plus

import "time"

func parseUTCTime(_ string) (time.Time, error) {
	return time.Time{}, mkerr("Deprecated UTCTime not enabled")
}

func fillTemporalHooks[T Temporal](
	enc EncodeOverride[T],
	dec DecodeOverride[T],
) (EncodeOverride[T], DecodeOverride[T]) {

	if enc != nil && dec != nil {
		return enc, dec
	}

	rt := derefTypePtr(refTypeOf((*T)(nil)).Elem())

	switch {
	case attachDefaults[TimeOfDay](rt, &enc, &dec, encTimeOfDay, decTimeOfDay):
	case attachDefaults[GeneralizedTime](rt, &enc, &dec, encGeneralizedTime, decGeneralizedTime):
	case attachDefaults[DateTime](rt, &enc, &dec, encDateTime, decDateTime):
	case attachDefaults[Date](rt, &enc, &dec, encDate, decDate):
	case attachDefaults[Time](rt, &enc, &dec, encTime, decTime):
	default:
		panic("RegisterTemporalAlias: please provide encode/decode hooks for custom temporal type")
	}

	return enc, dec
}
