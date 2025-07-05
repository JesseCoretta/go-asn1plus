//go:build !asn1_no_adapter_pf

package asn1plus

import (
	"math/big"
	"time"
)

// wrapTemporalStringCtor adapts a temporal constructor that wants
// (time.Time, ...Constraint[Temporal]) so it can be fed with a string.
func wrapTemporalStringCtor[T any](
	raw func(any, ...Constraint[Temporal]) (T, error),
	parse parseFn,
) func(string, ...Constraint[T]) (T, error) {

	return func(s string, cs ...Constraint[T]) (t T, err error) {
		var tm time.Time
		t = *new(T)
		if tm, err = parse(s); err == nil {
			tc := make([]Constraint[Temporal], len(cs))
			for i, c := range cs {
				cc := c
				tc[i] = func(x Temporal) error { return cc(x.(T)) }
			}
			t, err = raw(tm, tc...)
		}
		return
	}
}

func wrapRealCtor[GoT any](
	base int,
	toComponents func(GoT, int) (mant any, exp int, err error),
) func(GoT, ...Constraint[Real]) (Real, error) {

	return func(v GoT, cs ...Constraint[Real]) (Real, error) {
		m, e, err := toComponents(v, base)
		var r Real
		if err == nil {
			r, err = NewReal(m, base, e, cs...)
		}
		return r, err
	}
}

/*
wrapOIDCtor is a special adapter "converter" to help deal with the OID constructor's
slightly different (but functionally equivalent) input signature.
*/
func wrapOIDCtor[S any](
	raw func(...any) (ObjectIdentifier, error),
	convert func(S) any,
) func(S, ...Constraint[ObjectIdentifier]) (ObjectIdentifier, error) {
	return func(s S, cs ...Constraint[ObjectIdentifier]) (ObjectIdentifier, error) {
		args := make([]any, 1+len(cs))
		args[0] = convert(s)
		for i, c := range cs {
			args[i+1] = c
		}
		return raw(args...)
	}
}

/*
wrapRelOIDCtor is a special adapter "converter" to help deal with the RelativeOID
constructor's slightly different (but functionally equivalent) input signature.
*/
func wrapRelOIDCtor[S any](
	raw func(...any) (RelativeOID, error),
	convert func(S) any,
) func(S, ...Constraint[RelativeOID]) (RelativeOID, error) {
	return func(s S, cs ...Constraint[RelativeOID]) (RelativeOID, error) {
		args := make([]any, 1+len(cs))
		args[0] = convert(s)
		for i, c := range cs {
			args[i+1] = c
		}
		return raw(args...)
	}
}

/*
wrapTemporalCtor is a special adapter "converter" to help deal with the Temporal
constraint signature for Temporal types.
*/
func wrapTemporalCtor[T any](
	raw func(any, ...Constraint[Temporal]) (T, error),
) func(time.Time, ...Constraint[T]) (T, error) {

	return func(t time.Time, cs ...Constraint[T]) (T, error) {
		tc := make([]Constraint[Temporal], len(cs))
		for i, c := range cs {
			cc := c
			tc[i] = func(x Temporal) error { return cc(x.(T)) }
		}
		return raw(t, tc...)
	}
}

func registerMiscAdapters() {
	RegisterAdapter[Duration, string](
		func(s string, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(s, cs...)
		},
		func(p *Duration) string { return p.String() },
		"duration",
	)

	RegisterAdapter[Duration, time.Duration](
		func(td time.Duration, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(td, cs...)
		},
		func(p *Duration) time.Duration { return p.Duration() },
		"", "duration",
	)

	RegisterAdapter[Duration, int64](
		func(td int64, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(time.Duration(td), cs...)
		},
		func(p *Duration) int64 { return int64(p.Duration()) },
		"duration",
	)

	// string <-> ObjectIdentifier. Note that we perform special
	// "wrapping" here to account for a slightly different input
	// signature on part of the ObjectIdentifier constructor.
	RegisterAdapter[ObjectIdentifier, string](
		wrapOIDCtor(NewObjectIdentifier, func(s string) any { return s }),
		func(p *ObjectIdentifier) string { return p.String() },
		"", "oid", "objectidentifier", "object-identifier",
	)

	// ditto for RelativeOID
	RegisterAdapter[RelativeOID, string](
		wrapRelOIDCtor(NewRelativeOID, func(s string) any { return s }),
		func(p *RelativeOID) string { return p.String() },
		"relativeoid", "relative-oid", "reloid",
	)

	RegisterAdapter[ObjectDescriptor, string](
		func(s string, cs ...Constraint[ObjectDescriptor]) (ObjectDescriptor, error) {
			return NewObjectDescriptor(s, cs...)
		},
		func(p *ObjectDescriptor) string { return string(*p) },
		"descriptor", "objectdescriptor", "object-descriptor",
	)

	RegisterAdapter[Boolean, bool](
		func(b bool, cs ...Constraint[Boolean]) (Boolean, error) {
			return NewBoolean(b, cs...)
		},
		func(p *Boolean) bool { return bool(*p) },
		"", "boolean", "bool",
	)
}

func registerTemporalAliasAdapters() {
	RegisterAdapter[GeneralizedTime, time.Time](
		wrapTemporalCtor[GeneralizedTime](NewGeneralizedTime),
		func(p *GeneralizedTime) time.Time { return time.Time(*p) },
		"gt", "generalizedtime", "generalized-time",
	)

	RegisterAdapter[Date, time.Time](
		wrapTemporalCtor[Date](NewDate),
		func(p *Date) time.Time { return time.Time(*p) },
		"date",
	)

	RegisterAdapter[DateTime, time.Time](
		wrapTemporalCtor[DateTime](NewDateTime),
		func(p *DateTime) time.Time { return time.Time(*p) },
		"date-time", "datetime",
	)

	RegisterAdapter[TimeOfDay, time.Time](
		wrapTemporalCtor[TimeOfDay](NewTimeOfDay),
		func(p *TimeOfDay) time.Time { return time.Time(*p) },
		"time-of-day", "timeofday",
	)

	RegisterAdapter[Time, time.Time](
		wrapTemporalCtor[Time](NewTime),
		func(p *Time) time.Time { return time.Time(*p) },
		"time",
	)

	RegisterAdapter[GeneralizedTime, string](
		wrapTemporalStringCtor[GeneralizedTime](NewGeneralizedTime, parseGeneralizedTime),
		func(p *GeneralizedTime) string { return formatGeneralizedTime(time.Time(*p)) },
		"gt", "generalizedtime",
	)

	RegisterAdapter[Date, string](
		wrapTemporalStringCtor[Date](NewDate, parseDate),
		func(p *Date) string { return formatDate(time.Time(*p)) },
		"date",
	)

	RegisterAdapter[DateTime, string](
		wrapTemporalStringCtor[DateTime](NewDateTime, parseDateTime),
		func(p *DateTime) string { return formatDateTime(time.Time(*p)) },
		"date-time", "datetime",
	)

	RegisterAdapter[TimeOfDay, string](
		wrapTemporalStringCtor[TimeOfDay](NewTimeOfDay, parseTimeOfDay),
		func(p *TimeOfDay) string { return formatTimeOfDay(time.Time(*p)) },
		"time-of-day", "timeofday",
	)

	RegisterAdapter[Time, string](
		wrapTemporalStringCtor[Time](NewTime, parseTime),
		func(p *Time) string { return formatTime(time.Time(*p)) },
		"time",
	)
}

func registerNumericalAdapters() {
	RegisterAdapter[Integer, int](
		func(n int, cs ...Constraint[Integer]) (Integer, error) {
			return NewInteger(int64(n), cs...)
		},
		func(p *Integer) int {
			if p.big {
				return int(p.Big().Int64())
			}
			return int(p.native)
		},
		"int", "integer",
	)

	RegisterAdapter[Integer, *big.Int](
		func(bi *big.Int, cs ...Constraint[Integer]) (Integer, error) {
			return NewInteger(bi, cs...)
		},
		func(p *Integer) *big.Int { return p.Big() },
		"int", "integer",
	)

	RegisterAdapter[Enumerated, int](
		func(n int, cs ...Constraint[Enumerated]) (Enumerated, error) {
			return NewEnumerated(n, cs...)
		},
		func(p *Enumerated) int { return int(*p) },
		"enum", "enumerated",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(2, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real2",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(8, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real8",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(10, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"", "real10", "real",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(16, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real16",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(2, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real2",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(8, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real8",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(10, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real10",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(16, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real16",
	)
}

func registerStringAdapters() {
	// string <-> UTF8STring [string default!]
	RegisterAdapter[UTF8String, string](
		func(s string, cs ...Constraint[UTF8String]) (UTF8String, error) {
			return NewUTF8String(s, cs...)
		},
		func(p *UTF8String) string { return string(*p) },
		"", "utf8string", "utf8",
	)

	RegisterAdapter[NumericString, string](
		func(s string, cs ...Constraint[NumericString]) (NumericString, error) {
			return NewNumericString(s, cs...)
		},
		func(p *NumericString) string { return string(*p) },
		"numeric", "numericstring",
	)

	RegisterAdapter[PrintableString, string](
		func(s string, cs ...Constraint[PrintableString]) (PrintableString, error) {
			return NewPrintableString(s, cs...)
		},
		func(p *PrintableString) string { return string(*p) },
		"printable", "printablestring",
	)

	RegisterAdapter[VisibleString, string](
		func(s string, cs ...Constraint[VisibleString]) (VisibleString, error) {
			return NewVisibleString(s, cs...)
		},
		func(p *VisibleString) string { return string(*p) },
		"visible", "visiblestring",
	)

	RegisterAdapter[OctetString, string](
		func(s string, cs ...Constraint[OctetString]) (OctetString, error) {
			return NewOctetString(s, cs...)
		},
		func(p *OctetString) string { return string(*p) },
		"octet", "octetstring",
	)

	RegisterAdapter[IA5String, string](
		func(s string, cs ...Constraint[IA5String]) (IA5String, error) {
			return NewIA5String(s, cs...)
		},
		func(p *IA5String) string { return string(*p) },
		"ia5", "ia5string",
	)

	RegisterAdapter[BMPString, string](
		func(s string, cs ...Constraint[BMPString]) (BMPString, error) {
			return NewBMPString(s, cs...)
		},
		func(p *BMPString) string { return string(*p) },
		"bmp", "bmpstring",
	)

	RegisterAdapter[UniversalString, string](
		func(s string, cs ...Constraint[UniversalString]) (UniversalString, error) {
			return NewUniversalString(s, cs...)
		},
		func(p *UniversalString) string { return string(*p) },
		"universal", "universalstring",
	)

	RegisterAdapter[OctetString, []byte](
		func(s []byte, cs ...Constraint[OctetString]) (OctetString, error) {
			return NewOctetString(s, cs...)
		},
		func(p *OctetString) []byte { return []byte(*p) },
		"octet", "octetstring",
	)

	RegisterAdapter[BitString, []byte](
		func(s []byte, cs ...Constraint[BitString]) (BitString, error) {
			return NewBitString(s, cs...)
		},
		func(p *BitString) []byte { return []byte(p.Bytes) },
		"bit", "bitstring",
	)
}

func init() {
	registerStringAdapters()
	registerNumericalAdapters()
	registerTemporalAliasAdapters()
	registerMiscAdapters()
}
