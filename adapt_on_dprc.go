//go:build !asn1_no_dprc && !asn1_no_adapter_pf

package asn1plus

import "time"

func registerDeprecatedAdapters() {
	RegisterAdapter[GraphicString, string](
		func(s string, cs ...Constraint[GraphicString]) (GraphicString, error) {
			return NewGraphicString(s, cs...)
		},
		func(p *GraphicString) string { return string(*p) },
		"graphic", "graphicstring",
	)

	RegisterAdapter[VideotexString, string](
		func(s string, cs ...Constraint[VideotexString]) (VideotexString, error) {
			return NewVideotexString(s, cs...)
		},
		func(p *VideotexString) string { return string(*p) },
		"videotex", "videotexstring",
	)

	RegisterAdapter[GeneralString, string](
		func(s string, cs ...Constraint[GeneralString]) (GeneralString, error) {
			return NewGeneralString(s, cs...)
		},
		func(p *GeneralString) string { return string(*p) },
		"general", "generalstring",
	)

	RegisterAdapter[T61String, string](
		func(s string, cs ...Constraint[T61String]) (T61String, error) {
			return NewT61String(s, cs...)
		},
		func(p *T61String) string { return string(*p) },
		"t61", "t61string", "teletex", "teletexstring",
	)

	RegisterAdapter[UTCTime, string](
		wrapTemporalStringCtor[UTCTime](NewUTCTime, parseUTCTime),
		func(p *UTCTime) string { return formatUTCTime(time.Time(*p)) },
		"utc", "utctime",
	)

	RegisterAdapter[UTCTime, time.Time](
		wrapTemporalCtor[UTCTime](NewUTCTime),
		func(p *UTCTime) time.Time { return time.Time(*p) },
		"utc", "utctime", "utc-time",
	)
}

func init() {
	registerDeprecatedAdapters()
}
