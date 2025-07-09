//go:build !asn1_no_dprc

package asn1plus

import "time"

/*
Deprecated: UTCTime aliases an instance of [time.Time] to implement the
obsolete ASN.1 UTC TIME (tag 23)

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type UTCTime Time

/*
UTCTimeConstraintPhase declares the appropriate phase for
the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var UTCTimeConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagUTCTime].
*/
func (r UTCTime) Tag() int { return TagUTCTime }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r UTCTime) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r UTCTime) String() string { return formatUTCTime(r.Cast()) }

/*
Layout returns the string literal "0601021504". Note that the
terminating Zulu (Z) character is not included, as it is not
used wherever a UTC offset value is desired (e.g.: -0700).
*/
func (r UTCTime) Layout() string { return uTCTimeLayout }

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r UTCTime) Cast() time.Time { return time.Time(r) }

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r UTCTime) Eq(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Equal(in)
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r UTCTime) Ne(t Temporal) bool {
	in := truncateBy(t, t)
	return !r.Cast().Equal(in)
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r UTCTime) Lt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Before(in)
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r UTCTime) Le(t Temporal) bool { return r.Lt(t) || r.Eq(t) }

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r UTCTime) Gt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().After(in)
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r UTCTime) Ge(t Temporal) bool { return r.Gt(t) || r.Eq(t) }

/*
Deprecated: UTCTime is intended for historical support only; use [GeneralizedTime]
instead.

NewUTCTime returns an instance of [UTCTime] alongside an error following an attempt
to marshal x.
*/
func NewUTCTime(x any, constraints ...Constraint[Temporal]) (utc UTCTime, err error) {
	var (
		format string = `0601021504` // kept for legacy fallback
		sec    string = `05`
		diff   string = `-0700`
		raw    string
		_utc   UTCTime
	)

	switch tv := x.(type) {
	case string:
		raw = tv // keep the Z / ±hhmm intact for fast path
	default:
		err = errorBadTypeForConstructor("UTC TIME", x)
	}

	if err == nil {
		var t time.Time
		if t, err = parseUTCTime(raw); err == nil {
			_utc = UTCTime(t)
		} else {
			// legacy slow path for rare corner cases
			raw = chopZulu(raw)
			if len(raw) < 10 {
				err = mkerr("Invalid ASN.1 UTC TIME")
			} else {
				_utc, err = uTCHandler(raw, sec, diff, format)
			}
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(UTCTime(_utc))
	}

	if err == nil {
		utc = _utc
	}
	return utc, err
}

func utcDigit(b byte) bool     { return '0' <= b && b <= '9' }
func utcToInt(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }

func parseUTCCore(s string) (yy, mm, dd, hr, mn, sc, next int, err error) {
	// need at least “YYMMDDhhmmZ” → 11 bytes
	if len(s) < 11 {
		err = mkerr("Invalid ASN.1 UTC TIME")
		return
	}

	// first ten must be digits
	for k := 0; k < 10; k++ {
		if !utcDigit(s[k]) {
			err = mkerr("Invalid ASN.1 UTC TIME")
			return
		}
	}

	if len(s) >= 12 && utcDigit(s[11]) {
		err = mkerr("Invalid ASN.1 UTC TIME")
		return
	}

	hasSec := utcDigit(s[10])
	yy = utcToInt(s[0], s[1])
	mm = utcToInt(s[2], s[3])
	dd = utcToInt(s[4], s[5])
	hr = utcToInt(s[6], s[7])
	mn = utcToInt(s[8], s[9])

	if hasSec {
		sc = utcToInt(s[10], s[11])
		next = 12
		if len(s) < 13 {
			err = mkerr("Invalid ASN.1 UTC TIME")
		}
	} else {
		sc = 0
		next = 10
	}

	return
}

func parseUTCTimezone(s string, idx int) (loc *time.Location, err error) {
	if idx >= len(s) {
		return nil, mkerr("Invalid ASN.1 UTC TIME")
	}

	switch s[idx] {
	case 'Z':
		if idx != len(s)-1 {
			return nil, mkerr("Invalid ASN.1 UTC TIME")
		}
		return time.UTC, nil

	case '+', '-':
		if idx+5 != len(s) {
			return nil, mkerr("Invalid ASN.1 UTC TIME")
		}
		for k := 1; k <= 4; k++ {
			if !utcDigit(s[idx+k]) {
				return nil, mkerr("Invalid ASN.1 UTC TIME")
			}
		}
		hh := utcToInt(s[idx+1], s[idx+2])
		mm := utcToInt(s[idx+3], s[idx+4])
		if hh > 23 || mm > 59 {
			return nil, mkerr("Invalid ASN.1 UTC TIME")
		}
		off := (hh*60 + mm) * 60
		if s[idx] == '-' {
			off = -off
		}
		return time.FixedZone("", off), nil
	default:
		return nil, mkerr("Invalid ASN.1 UTC TIME")
	}
}

func parseUTCTime(s string) (utc time.Time, err error) {
	var yy, mo, dd, hr, mn, sc, i int
	if yy, mo, dd, hr, mn, sc, i, err = parseUTCCore(s); err == nil {
		var loc *time.Location
		if loc, err = parseUTCTimezone(s, i); err == nil {
			// two-digit year mapping (50-99 ⇒ 19xx, 00-49 ⇒ 20xx)
			if yy < 50 {
				yy += 2000
			} else {
				yy += 1900
			}

			utc = time.Date(yy, time.Month(mo), dd, hr, mn, sc, 0, loc)
		}
	}

	return
}

func formatUTCTime(t time.Time) string {
	var b [11]byte // YYMMDDhhmm + 'Z'
	put2 := func(idx, v int) {
		b[idx] = byte('0' + v/10)
		b[idx+1] = byte('0' + v%10)
	}
	yy := t.Year() % 100
	put2(0, yy)
	put2(2, int(t.Month()))
	put2(4, t.Day())
	put2(6, t.Hour())
	put2(8, t.Minute())
	b[10] = 'Z'
	return string(b[:])
}

func decUTCTime(b []byte) (UTCTime, error) {
	t, err := parseUTCTime(string(b))
	return UTCTime(t), err
}

func encUTCTime(d UTCTime) ([]byte, error) {
	return []byte(formatUTCTime(time.Time(d))), nil
}

func uTCHandler(raw, sec, diff, format string) (utc UTCTime, err error) {
	var _utc time.Time

	switch len(raw) {
	case 10:
		if _utc, err = time.Parse(format, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	case 12:
		if _utc, err = time.Parse(format+sec, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	}

	format += sec

	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	if _utc, err = time.Parse(format, raw); err == nil {
		utc = UTCTime(_utc)
	}

	return
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
	case attachDefaults[UTCTime](rt, &enc, &dec, encUTCTime, decUTCTime):
	case attachDefaults[DateTime](rt, &enc, &dec, encDateTime, decDateTime):
	case attachDefaults[Date](rt, &enc, &dec, encDate, decDate):
	case attachDefaults[Time](rt, &enc, &dec, encTime, decTime):
	default:
		panic("RegisterTemporalAlias: please provide encode/decode hooks for custom temporal type")
	}

	return enc, dec
}

func init() {
	RegisterTemporalAlias[UTCTime](TagUTCTime,
		UTCTimeConstraintPhase, nil, nil, nil, nil)
}
