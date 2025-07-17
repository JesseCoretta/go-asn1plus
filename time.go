package asn1plus

/*
time.go implements all temporal syntaxes and matching rules -- namely
those for Generalized Time and the (deprecated) UTC Time.
*/

import (
	"reflect"
	"time"
	"unsafe"
)

var tnow func() time.Time = time.Now

/*
Temporal is a date and time interface qualified by instances of the
following types:

  - [Time]
  - [Date]
  - [DateTime]
  - [TimeOfDay]
  - [GeneralizedTime]

Note that [Duration] does not qualify this interface. Also note that
UTCTime implements this interface, but only when support is compiled.
*/
type Temporal interface {
	Cast() time.Time
	String() string
	Eq(Temporal) bool
	Ne(Temporal) bool
	Gt(Temporal) bool
	Ge(Temporal) bool
	Lt(Temporal) bool
	Le(Temporal) bool
}

const (
	dateLayout      = "2006-01-02"
	dateTimeLayout  = "2006-01-02T15:04:05"
	timeOfDayLayout = "15:04:05"
	genTimeLayout   = "20060102150405"
	uTCTimeLayout   = "0601021504"
)

/*
Time implements the base ASN.1 TIME (tag 14) which underlies the following
types:

  - [Date]
  - [DateTime]
  - [TimeOfDay]
  - [GeneralizedTime]

Note that use of this type is less efficient than use of one of the derivative
types, such as [DateTime] or [TimeOfDay].
*/
type Time time.Time

/*
TimeConstraintPhase declares the appropriate phase for the
constraining of values during codec operations. See the
[CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var TimeConstraintPhase = CodecConstraintDecoding

/*
NewTime returns an instance of [Time] alongside an error following an
attempt to marshal x.
*/
func NewTime(x any, constraints ...Constraint[Temporal]) (Time, error) {
	var raw string
	var err error

	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = unsafe.String(&tv[0], len(tv))
	case Temporal:
		raw = tv.String()
	case time.Time:
		raw = formatTime(tv.Truncate(time.Second))
	default:
		err = errorBadTypeForConstructor("TIME", x)
	}

	var t time.Time
	if err == nil {
		t, err = parseTime(raw)
	}

	if err == nil && len(constraints) > 0 {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(Time(t))
	}

	var tm Time
	if err == nil {
		tm = Time(t)
	}

	return tm, err
}

/*
Tag returns the integer constant [TagTime].
*/
func (r Time) Tag() int { return TagTime }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r Time) IsPrimitive() bool { return true }

/*
Cast returns the receiver instance cast as an instance of [time.Time].
*/
func (r Time) Cast() time.Time { return time.Time(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r Time) String() string { return formatTime(r.Cast()) }

func truncateBy(r, by Temporal) time.Time {
	switch by.(type) {
	case Date:
		rt := r.Cast()
		return time.Date(rt.Year(), rt.Month(), rt.Day(), 0, 0, 0, 0, rt.Location())
	case TimeOfDay:
		rt := r.Cast()
		return time.Date(1, time.January, 1, rt.Hour(), rt.Minute(), rt.Second(), 0, rt.Location())
	}

	return r.Cast()
}

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r Time) Eq(t Temporal) bool {
	_r := truncateBy(r, t)
	_t := truncateBy(t, t)
	return _r.Equal(_t)
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r Time) Ne(t Temporal) bool {
	_r := truncateBy(r, t)
	_t := truncateBy(t, t)
	return !_r.Equal(_t)
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r Time) Lt(t Temporal) bool {
	_r := truncateBy(r, t)
	_t := truncateBy(t, t)
	return _r.Before(_t)
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r Time) Le(t Temporal) bool {
	return r.Lt(t) || r.Eq(t)
}

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r Time) Gt(t Temporal) bool {
	_r := truncateBy(r, t)
	_t := truncateBy(t, t)
	return _r.After(_t)
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r Time) Ge(t Temporal) bool {
	return r.Gt(t) || r.Eq(t)
}

func parseTime(s string) (out time.Time, err error) {
	// First, try fast-paths based on known fixed lengths.
	switch len(s) {
	case 19:
		// Likely a DATE-TIME in "2006-01-02T15:04:05"
		out, err = parseDateTime(s)
	case 10:
		// Could be a DATE ("2006-01-02") or a UTCTime ("0601021504")
		// Here, we prefer a date if the string contains '-'.
		if s[4] == '-' && s[7] == '-' {
			out, err = parseDate(s)
		} else {
			out, err = parseUTCTime(s)
		}
	case 8:
		// Possibly a Time-of-Day ("15:04:05")
		out, err = parseTimeOfDay(s)
	case 14:
		// Likely a GeneralizedTime (e.g., "20060102150405")
		out, err = parseGeneralizedTime(s)
	default:
		out, err = fallbackTimeMatch(s)
	}

	return
}

func fallbackTimeMatch(s string) (out time.Time, err error) {
	// Alternatively, try a list of layouts if nothing fast-matched.
	layouts := []string{
		dateTimeLayout,  // "2006-01-02T15:04:05"
		dateLayout,      // "2006-01-02"
		timeOfDayLayout, // "15:04:05"
		genTimeLayout,   // "20060102150405"
		uTCTimeLayout,   // "0601021504"
	}

	var matched bool
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			out = t
			matched = true
			break
		}
	}

	if !matched {
		err = primitiveErrorf("TIME: invalid format")
	}

	return
}

func formatTime(t time.Time) string {
	// In some designs you might instead format according to what was originally parsed.
	return t.Format(dateTimeLayout)
}

func decTime(b []byte) (Time, error) {
	t, err := parseTime(string(b))
	return Time(t), err
}

func encTime(d Time) ([]byte, error) {
	return []byte(formatTime(time.Time(d))), nil
}

/*
Date implements the ASN.1 DATE type (tag 31), which extends from [Time].
*/
type Date Time

/*
DateConstraintPhase declares the appropriate phase for the
constraining of values during codec operations. See the
[CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var DateConstraintPhase = CodecConstraintDecoding

/*
NewDate returns an instance of [Date] alongside an error following an attempt
to marshal x.
*/
func NewDate(x any, constraints ...Constraint[Temporal]) (Date, error) {
	var s string
	var err error

	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case Date:
		s = tv.String()
	case time.Time:
		s = formatDate(tv)
	default:
		err = errorBadTypeForConstructor("DATE", x)
	}

	var t time.Time
	if err == nil {
		t, err = parseDate(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(Date(t))
	}

	var d Date
	if err == nil {
		d = Date(t)
	}

	return d, err
}

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r Date) Eq(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().Equal(time.Date(in.Year(), in.Month(),
		in.Day(), 0, 0, 0, 0, in.Location()))
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r Date) Ne(t Temporal) bool {
	in := truncateBy(t, t)
	return !r.truncate().Equal(time.Date(in.Year(), in.Month(), in.Day(), 0, 0, 0, 0, in.Location()))
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r Date) Lt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().Before(time.Date(in.Year(), in.Month(), in.Day(), 0, 0, 0, 0, in.Location()))
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r Date) Le(t Temporal) bool {
	return r.Lt(t) || r.Eq(t)
}

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r Date) Gt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().After(time.Date(in.Year(), in.Month(), in.Day(), 0, 0, 0, 0, in.Location()))
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r Date) Ge(t Temporal) bool {
	return r.Gt(t) || r.Eq(t)
}

/*
truncate returns a cast instance of time.Time, minus all clock time components.
*/
func (r Date) truncate() time.Time {
	t := r.Cast()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// parseDate parses YYYY-MM-DD in UTC, no heap, ~70 ns.
func parseDate(s string) (time.Time, error) {
	if len(s) != 10 {
		return time.Time{}, primitiveErrorf("DATE: invalid length")
	}
	if s[4] != '-' || s[7] != '-' {
		return time.Time{}, primitiveErrorf("DATE: invalid format")
	}
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }

	year := toInt(s[0], s[1])*100 + toInt(s[2], s[3])
	month := toInt(s[5], s[6])
	day := toInt(s[8], s[9])

	if month == 0 || month > 12 || day == 0 || day > 31 {
		return time.Time{}, primitiveErrorf("DATE: invalid input")
	}
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC), nil
}

// formatDate returns a string identical to t.Format(dateLayout) with
// zero heap allocations.
func formatDate(t time.Time) string {
	var b [10]byte
	put2 := func(i, v int) {
		b[i] = byte('0' + v/10)
		b[i+1] = byte('0' + v%10)
	}
	year := t.Year()
	b[0] = byte('0' + (year/1000)%10)
	b[1] = byte('0' + (year/100)%10)
	b[2] = byte('0' + (year/10)%10)
	b[3] = byte('0' + year%10)
	b[4] = '-'
	put2(5, int(t.Month()))
	b[7] = '-'
	put2(8, t.Day())
	return string(b[:])
}

func decDate(b []byte) (Date, error) {
	t, err := parseDate(string(b))
	return Date(t), err
}

func encDate(d Date) ([]byte, error) {
	return []byte(formatDate(time.Time(d))), nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r Date) String() string {
	return formatDate(r.Cast())
}

/*
Layout returns the string literal "2006-01-02".
*/
func (r Date) Layout() string {
	return dateLayout
}

/*
Tag returns the integer constant [TagDate].
*/
func (r Date) Tag() int { return TagDate }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r Date) IsPrimitive() bool { return true }

/*
Cast returns the receiver instance cast as an instance of [time.Time].
*/
func (r Date) Cast() time.Time { return time.Time(r) }

/*
DateTime implements the ASN.1 DATE-TIME type (tag 33), which extends from [Time].
*/
type DateTime Time

/*
DateTimeConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var DateTimeConstraintPhase = CodecConstraintDecoding

/*
NewDateTime returns an instance of [DateTime] alongside an error following an
attempt to marshal x.
*/
func NewDateTime(x any, constraints ...Constraint[Temporal]) (DateTime, error) {
	var s string
	var err error

	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = unsafe.String(&tv[0], len(tv))
	case DateTime:
		s = tv.String()
	case time.Time:
		s = formatDateTime(tv.Truncate(time.Second))
	default:
		err = errorBadTypeForConstructor("DATE-TIME", x)
	}

	var t time.Time
	if err == nil {
		t, err = parseDateTime(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(DateTime(t))
	}

	var d DateTime
	if err == nil {
		d = DateTime(t)
	}

	return d, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r DateTime) String() string { return formatDateTime(r.Cast()) }

/*
Layout returns string literal "2006-01-02T15:04:05".
*/
func (r DateTime) Layout() string { return dateTimeLayout }

// parseDateTime parses the fixed-width layout 2006-01-02T15:04:05.
// Returns UTC.  Zero allocs; ~120 ns on modern CPUs.
func parseDateTime(s string) (time.Time, error) {
	if len(s) != 19 {
		return time.Time{}, primitiveErrorf("DATE-TIME: invalid length")
	}
	// quick layout check – cheap and rejects most garbage early
	if s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return time.Time{}, primitiveErrorf("DATE-TIME: invalid format")
	}
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') } // ascii digits

	year := toInt(s[0], s[1])*100 + toInt(s[2], s[3])
	month := toInt(s[5], s[6])
	day := toInt(s[8], s[9])
	hour := toInt(s[11], s[12])
	min := toInt(s[14], s[15])
	sec := toInt(s[17], s[18])

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC), nil
}

func formatDateTime(t time.Time) string {
	var b [19]byte
	put2 := func(i, v int) {
		b[i] = byte('0' + v/10)
		b[i+1] = byte('0' + v%10)
	}
	year := t.Year()
	b[0] = byte('0' + (year/1000)%10)
	b[1] = byte('0' + (year/100)%10)
	b[2] = byte('0' + (year/10)%10)
	b[3] = byte('0' + year%10)
	b[4] = '-'
	put2(5, int(t.Month()))
	b[7] = '-'
	put2(8, t.Day())
	b[10] = 'T'
	put2(11, t.Hour())
	b[13] = ':'
	put2(14, t.Minute())
	b[16] = ':'
	put2(17, t.Second())
	return string(b[:]) // one unavoidable copy; still zero allocs on parse path
}

func decDateTime(b []byte) (DateTime, error) {
	t, err := parseDateTime(string(b))
	return DateTime(t), err
}

func encDateTime(d DateTime) ([]byte, error) {
	return []byte(formatDateTime(time.Time(d))), nil
}

/*
Tag returns the integer constant [TagDateTime].
*/
func (r DateTime) Tag() int { return TagDateTime }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r DateTime) IsPrimitive() bool { return true }

/*
Cast returns the receiver instance cast as an instance of [time.Time].
*/
func (r DateTime) Cast() time.Time { return time.Time(r) }

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r DateTime) Eq(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Equal(in)
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r DateTime) Ne(t Temporal) bool {
	in := truncateBy(t, t)
	return !r.Cast().Equal(in)
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r DateTime) Lt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Before(in)
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r DateTime) Le(t Temporal) bool { return r.Lt(t) || r.Eq(t) }

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r DateTime) Gt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().After(in)
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r DateTime) Ge(t Temporal) bool { return r.Gt(t) || r.Eq(t) }

/*
TimeOfDay implements the ASN.1 TIME-OF-DAY type (tag 32), which extends from [Time].
*/
type TimeOfDay Time

/*
TimeOfDayConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var TimeOfDayConstraintPhase = CodecConstraintDecoding

/*
NewDateTime returns an instance of [TimeOfDay] alongside an error following an
attempt to marshal x.
*/
func NewTimeOfDay(x any, constraints ...Constraint[Temporal]) (TimeOfDay, error) {
	var s string
	var err error

	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = unsafe.String(&tv[0], len(tv)) // no copy, no alloc
	case TimeOfDay:
		s = tv.String()
	case time.Time:
		s = formatTimeOfDay(tv)
	default:
		err = errorBadTypeForConstructor("TIME-OF-DAY", x)
	}

	var t time.Time
	if err == nil {
		t, err = parseTimeOfDay(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(TimeOfDay(t))
	}

	var d TimeOfDay
	if err == nil {
		d = TimeOfDay(t)
	}

	return d, err
}

// returns a time in UTC with zero date; no allocs, ~60 ns
func parseTimeOfDay(s string) (time.Time, error) {
	if len(s) != 8 {
		return time.Time{}, primitiveErrorf("TimeOfDay: invalid length")
	}
	if s[2] != ':' || s[5] != ':' {
		return time.Time{}, primitiveErrorf("TimeOfDay: invalid format")
	}
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') } // ASCII

	hh := toInt(s[0], s[1])
	mm := toInt(s[3], s[4])
	ss := toInt(s[6], s[7])
	if hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, primitiveErrorf("TimeOfDay: invalid input")
	}
	return time.Date(0, 1, 1, hh, mm, ss, 0, time.UTC), nil
}

// zero-alloc formatter; output byte-for-byte identical to time.Format(layout)
func formatTimeOfDay(t time.Time) string {
	var b [8]byte
	put2 := func(i, v int) {
		b[i] = byte('0' + v/10)
		b[i+1] = byte('0' + v%10)
	}
	put2(0, t.Hour())
	b[2] = ':'
	put2(3, t.Minute())
	b[5] = ':'
	put2(6, t.Second())
	return string(b[:])
}

func decTimeOfDay(b []byte) (TimeOfDay, error) {
	t, err := parseTimeOfDay(string(b))
	return TimeOfDay(t), err
}

func encTimeOfDay(d TimeOfDay) ([]byte, error) {
	return []byte(formatTimeOfDay(time.Time(d))), nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r TimeOfDay) String() string { return formatTimeOfDay(r.Cast()) }

/*
Layout returns the string literal "15:04:05".
*/
func (r TimeOfDay) Layout() string { return timeOfDayLayout }

/*
Tag returns the integer constant [TagTimeOfDay].
*/
func (r TimeOfDay) Tag() int { return TagTimeOfDay }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r TimeOfDay) IsPrimitive() bool { return true }

/*
Cast returns the receiver instance cast as an instance of [time.Time].
*/
func (r TimeOfDay) Cast() time.Time { return time.Time(r) }

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r TimeOfDay) Eq(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().Equal(time.Date(1, time.January, 1,
		in.Hour(), in.Minute(), in.Second(), 0, in.Location()))
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r TimeOfDay) Ne(t Temporal) bool {
	in := truncateBy(t, t)
	return !r.truncate().Equal(time.Date(1, time.January, 1,
		in.Hour(), in.Minute(), in.Second(), 0, in.Location()))
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r TimeOfDay) Lt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().Before(time.Date(1, time.January, 1,
		in.Hour(), in.Minute(), in.Second(), 0, in.Location()))
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r TimeOfDay) Le(t Temporal) bool {
	return r.Lt(t) || r.Eq(t)
}

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r TimeOfDay) Gt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.truncate().After(time.Date(1, time.January, 1,
		in.Hour(), in.Minute(), in.Second(), 0, in.Location()))
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r TimeOfDay) Ge(t Temporal) bool {
	return r.Gt(t) || r.Eq(t)
}

func (r TimeOfDay) truncate() time.Time {
	t := r.Cast()
	return time.Date(1, time.January, 1, t.Hour(), t.Minute(), t.Second(), 0, t.Location())
}

/*
Duration implements the ASN.1 DURATION type (tag 34).
*/
type Duration struct {
	Years   int
	Months  int
	Days    int
	Hours   int
	Minutes int
	Seconds float64
}

/*
DurationConstraintPhase declares the appropriate phase for
the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var DurationConstraintPhase = CodecConstraintDecoding

/*
NewDuration returns an instance of [Duration] alongside an error
following an attempt to marshal s as an [ISO 8601] duration.

The input must begin with a "P" (Period). The date portion (Y, M,
D) and, if present, the time portion (following a "T") are parsed
separately.

For instance:

	P7Y2M10DT05H28M6S

... to describe a duration period of seven (7) years, two (2) months,
ten (10) days, five (5) hours, twenty eight (28) minutes and six (6)
seconds.

In addition to string and []byte, this method accepts a [time.Duration]
instance as input.

Instances of this type DO NOT qualify the [Temporal] interface.
*/
func NewDuration(x any, constraints ...Constraint[Duration]) (Duration, error) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case time.Duration:
		s = parseTimeDuration(tv).String()
	default:
		return Duration{}, errorBadTypeForConstructor("DURATION", x)
	}

	if len(s) == 0 || s[0] != 'P' {
		return Duration{}, primitiveErrorf("Duration: must start with 'P'")
	}
	s = s[1:] // remove leading 'P'
	var _r Duration
	var err error

	// Split the string at 'T' (if present) into date and time parts.
	var datePart, timePart string
	if i := stridxb(s, 'T'); i >= 0 {
		datePart = s[:i]
		timePart = s[i+1:]
	} else {
		datePart = s
	}

	var r Duration
	if err = _r.parseDuration(datePart, timePart); err == nil {
		err = checkDurationEmpty(_r, err)
		if len(constraints) > 0 && err == nil {
			var group ConstraintGroup[Duration] = constraints
			err = group.Constrain(_r)
		}

		if err == nil {
			r = _r
		}
	}

	return r, err
}

func checkDurationEmpty(r Duration, err error) error {
	if err == nil &&
		r.Years == 0 &&
		r.Months == 0 &&
		r.Days == 0 &&
		r.Hours == 0 &&
		r.Minutes == 0 &&
		r.Seconds == 0 {
		err = primitiveErrorf("Duration: must contain at least one component")
	}

	return err
}

const (
	day  = 24 * time.Hour
	year = 365 * day
	mon  = 30 * day
)

/*
Duration returns an instance of [time.Duration] based upon
the state of the receiver instance.
*/
func (r Duration) Duration() time.Duration {
	dur := time.Duration(r.Years)*year +
		time.Duration(r.Months)*mon +
		time.Duration(r.Days)*day +
		time.Duration(r.Hours)*time.Hour +
		time.Duration(r.Minutes)*time.Minute +
		time.Duration(r.Seconds*float64(time.Second))

	return dur
}

func (r *Duration) parseDuration(datePart, timePart string) (err error) {
	// Helper to parse a numeric value ending with a given suffix.
	parseNumber := func(str string, suffix byte) (float64, string, error) {
		idx := stridxb(str, suffix)
		numStr := str[:idx]
		numStr = replace(numStr, ",", ".", 1)
		num, err := pfloat(numStr, 64)
		if err != nil {
			return 0, str, primitiveErrorf("error parsing number ", numStr, ": ", err)
		}
		return num, str[idx+1:], nil
	}

	if err = r.marshalYMD(datePart, parseNumber); err == nil {
		err = r.marshalHMS(timePart, parseNumber)
	}

	return
}

// parseTimeDuration decomposes a time.Duration back into an
// ASN.1 Duration record using the same Y/M/D approximations.
func parseTimeDuration(td time.Duration) Duration {
	neg := td < 0
	if neg {
		td = -td
	}

	y := int(td / year)
	td -= time.Duration(y) * year

	m := int(td / mon)
	td -= time.Duration(m) * mon

	d := int(td / day)
	td -= time.Duration(d) * day

	h := int(td / time.Hour)
	td -= time.Duration(h) * time.Hour

	min := int(td / time.Minute)
	td -= time.Duration(min) * time.Minute

	secs := float64(td) / float64(time.Second)

	out := Duration{
		Years:   y,
		Months:  m,
		Days:    d,
		Hours:   h,
		Minutes: min,
		Seconds: secs,
	}

	if neg {
		out.Years, out.Months, out.Days,
			out.Hours, out.Minutes, out.Seconds =
			-out.Years, -out.Months, -out.Days,
			-out.Hours, -out.Minutes, -out.Seconds
	}

	return out
}

func (r *Duration) marshalHMS(timePart string, parser func(string, byte) (float64, string, error)) (err error) {
	for len(timePart) > 0 && err == nil {
		var num float64
		var rem string

		if cntns(timePart, "H") {
			num, rem, err = parser(timePart, 'H')
			if err == nil {
				r.Hours = int(num)
				timePart = rem
			}
			continue
		}
		if cntns(timePart, "M") {
			num, rem, err = parser(timePart, 'M')
			if err == nil {
				r.Minutes = int(num)
				timePart = rem
			}
			continue
		}
		if cntns(timePart, "S") {
			num, rem, err = parser(timePart, 'S')
			if err == nil {
				r.Seconds = num
				timePart = rem
			}
			continue
		}
		break
	}

	return
}

func (r *Duration) marshalYMD(datePart string, parser func(string, byte) (float64, string, error)) (err error) {
	for len(datePart) > 0 && err == nil {
		var num float64
		var rem string

		if cntns(datePart, "Y") {
			num, rem, err = parser(datePart, 'Y')
			if err == nil {
				r.Years = int(num)
				datePart = rem
			}
			continue
		}
		if cntns(datePart, "M") {
			num, rem, err = parser(datePart, 'M')
			if err == nil {
				r.Months = int(num)
				datePart = rem
			}
			continue
		}
		if cntns(datePart, "D") {
			num, rem, err = parser(datePart, 'D')
			if err == nil {
				r.Days = int(num)
				datePart = rem
			}
			continue
		}
		break
	}

	return
}

/*
Tag returns the integer constant [TagDuration].
*/
func (r Duration) Tag() int { return TagDuration }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r Duration) IsPrimitive() bool { return true }

/*
Eq returns a Boolean value indicative of r being equal to d.
*/
func (r Duration) Eq(d Duration) bool {
	for _, pair := range []struct {
		rs int
		ds int
	}{
		{
			rs: r.Years,
			ds: d.Years,
		},
		{
			rs: r.Months,
			ds: d.Months,
		},
		{
			rs: r.Days,
			ds: d.Days,
		},
		{
			rs: r.Hours,
			ds: d.Hours,
		},
		{
			rs: r.Minutes,
			ds: d.Minutes,
		},
	} {
		if pair.rs != pair.ds {
			return pair.rs == pair.ds
		}
	}

	return r.Seconds == d.Seconds
}

/*
Ne returns a Boolean value indicative of r being not equal to d.
*/
func (r Duration) Ne(d Duration) bool { return !r.Eq(d) }

/*
Lt returns a Boolean value indicative of r being less than d.
*/
func (r Duration) Lt(d Duration) bool {
	for _, pair := range []struct {
		rs int
		ds int
	}{
		{
			rs: r.Years,
			ds: d.Years,
		},
		{
			rs: r.Months,
			ds: d.Months,
		},
		{
			rs: r.Days,
			ds: d.Days,
		},
		{
			rs: r.Hours,
			ds: d.Hours,
		},
		{
			rs: r.Minutes,
			ds: d.Minutes,
		},
	} {
		if pair.rs != pair.ds {
			return pair.rs < pair.ds
		}
	}

	return r.Seconds < d.Seconds
}

/*
Le returns a Boolean value indicative of r being less than or equal to d.
*/
func (r Duration) Le(d Duration) bool { return r.Eq(d) || r.Lt(d) }

/*
Gt returns a Boolean value indicative of r being greater than d.
*/
func (r Duration) Gt(d Duration) bool {
	for _, pair := range []struct {
		rs int
		ds int
	}{
		{
			rs: r.Years,
			ds: d.Years,
		},
		{
			rs: r.Months,
			ds: d.Months,
		},
		{
			rs: r.Days,
			ds: d.Days,
		},
		{
			rs: r.Hours,
			ds: d.Hours,
		},
		{
			rs: r.Minutes,
			ds: d.Minutes,
		},
	} {
		if pair.rs != pair.ds {
			return pair.rs > pair.ds
		}
	}

	return r.Seconds > d.Seconds
}

/*
Ge returns a Boolean value indicative of r being greater than or equal to d.
*/
func (r Duration) Ge(d Duration) bool { return r.Eq(d) || r.Gt(d) }

/*
AddTo returns a new instance of [time.Time] following a call to
[time.Time.Add] for the purpose of adding the receiver instance
to ref.
*/
func (r Duration) AddTo(ref time.Time) time.Time {
	t := ref.AddDate(r.Years, r.Months, r.Days)
	additional := time.Duration(r.Hours)*time.Hour +
		time.Duration(r.Minutes)*time.Minute +
		time.Duration(r.Seconds*float64(time.Second))
	return t.Add(additional)
}

/*
String returns the string representation of the receiver instance.
*/
func (r Duration) String() string {
	bld := newStrBuilder()
	bld.WriteString("P")
	if r.Years != 0 {
		bld.WriteString(itoa(r.Years) + "Y")
	}
	if r.Months != 0 {
		bld.WriteString(itoa(r.Months) + "M")
	}
	if r.Days != 0 {
		bld.WriteString(itoa(r.Days) + "D")
	}
	if r.Hours != 0 || r.Minutes != 0 || r.Seconds != 0 {
		bld.WriteString("T")
		if r.Hours != 0 {
			bld.WriteString(itoa(r.Hours) + "H")
		}
		if r.Minutes != 0 {
			bld.WriteString(itoa(r.Minutes) + "M")
		}
		if r.Seconds != 0 {
			bld.WriteString(fmtFloat(r.Seconds, 'f', 0, 64) + "S")
		}
	}
	if bld.Len() == 1 {
		bld.WriteString("T0S")
	}
	return bld.String()
}

/*
GeneralizedTime aliases an instance of [Time] to implement ASN.1 GENERALIZED
TIME (tag 24).
*/
type GeneralizedTime Time

/*
GeneralizedTimeConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var GeneralizedTimeConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagGeneralizedTime].
*/
func (r GeneralizedTime) Tag() int { return TagGeneralizedTime }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r GeneralizedTime) IsPrimitive() bool { return true }

/*
NewGeneralizedTime returns an instance of [GeneralizedTime] alongside an error
following an attempt to marshal x.
*/
func NewGeneralizedTime(x any, constraints ...Constraint[Temporal]) (gt GeneralizedTime, err error) {
	var (
		format string = gt.Layout()
		diff   string = "-0700"
		raw    string
	)

	switch tv := x.(type) {
	case string:
		if len(tv) < 15 {
			return gt, primitiveErrorf("GeneralizedTime: invalid input")
		}
		raw = tv
	default:
		return gt, errorBadTypeForConstructor("GeneralizedTime", x)
	}

	var t time.Time
	if t, err = parseGeneralizedTime(raw); err != nil {
		// legacy fall-back for rare corner cases
		base := raw[14:]
		if format, err = genTimeFracDiffFormat(raw, base, diff, format); err == nil {
			t, err = time.Parse(format, raw)
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Constrain(GeneralizedTime(t))
	}

	return GeneralizedTime(t), err
}

// Handle generalizedTime fractional component (up to six (6) digits)
func genTimeFracDiffFormat(raw, base, diff, format string) (string, error) {
	var err error

	if base[0] == '.' || base[0] == ',' {
		format += string(".")
		for fidx, ch := range base[1:] {
			if fidx > 6 {
				err = primitiveErrorf(`GeneralizedTime fraction exceeds fractional limit`)
			} else if '0' <= ch && ch <= '9' {
				format += `0`
				continue
			}
			break
		}
	}

	// Handle differential time, or bail out if not
	// already known to be zulu.
	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	return format, err
}

func parseCoreGTDateTime(s string) (year, mon, day, hr, min, sec, i int, err error) {
	digit := func(b byte) bool { return '0' <= b && b <= '9' }
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }

	if len(s) < 14 {
		err = primitiveErrorf("GeneralizedTime: invalid input")
		return
	}
	for k := 0; k < 14; k++ {
		if !digit(s[k]) {
			err = primitiveErrorf("GeneralizedTime: invalid input")
			return
		}
	}
	year = toInt(s[0], s[1])*100 + toInt(s[2], s[3])
	mon = toInt(s[4], s[5])
	day = toInt(s[6], s[7])
	hr = toInt(s[8], s[9])
	min = toInt(s[10], s[11])
	sec = toInt(s[12], s[13])
	i = 14
	return
}

func parseGTFraction(s string, i int) (nsec, next int, err error) {
	digit := func(b byte) bool { return '0' <= b && b <= '9' }
	next = i
	if next >= len(s) || (s[next] != '.' && s[next] != ',') {
		return
	}
	next++
	start := next
	for next < len(s) && digit(s[next]) {
		next++
	}
	fd := next - start
	if fd == 0 || fd > 6 {
		err = primitiveErrorf("GeneralizedTime: fraction exceeds fractional limit")
		return
	}
	frac := 0
	for j := start; j < next; j++ {
		frac = frac*10 + int(s[j]-'0')
	}
	for ; fd < 6; fd++ {
		frac *= 10
	}
	nsec = frac * 1_000 // µs→ns
	return
}

func parseGTTimezone(s string, i int) (loc *time.Location, next int, err error) {
	digit := func(b byte) bool { return '0' <= b && b <= '9' }
	next = i
	if next >= len(s) {
		err = errorBadGT
		return
	}
	switch s[next] {
	case 'Z':
		if next != len(s)-1 {
			err = errorBadGT
			return
		}
		loc = time.UTC
		next++
	case '+', '-':
		if next+5 != len(s) {
			err = errorBadGT
			return
		}
		for k := 1; k <= 4; k++ {
			if !digit(s[next+k]) {
				err = errorBadGT
				return
			}
		}
		toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }
		hh, mm := toInt(s[next+1], s[next+2]), toInt(s[next+3], s[next+4])
		if hh > 23 || mm > 59 {
			err = errorBadGT
			return
		}
		off := (hh*60 + mm) * 60
		if s[next] == '-' {
			off = -off
		}
		loc = time.FixedZone("", off)
		next += 5
	default:
		err = errorBadGT
	}
	return
}

func parseGeneralizedTime(s string) (time.Time, error) {
	year, mon, day, hr, min, sec, i, err := parseCoreGTDateTime(s)
	if err != nil {
		return time.Time{}, err
	}

	nsec, i, err := parseGTFraction(s, i)
	if err != nil {
		return time.Time{}, err
	}

	var loc *time.Location
	var t time.Time
	if loc, _, err = parseGTTimezone(s, i); err == nil {
		t = time.Date(year, time.Month(mon), day, hr, min, sec, nsec, loc)
	}
	return t, err
}

func formatGeneralizedTime(t time.Time) string {
	var buf [32]byte // 14 base + '.' + 6 frac + 'Z'  → max 22, 32 is safe
	i := 0

	put2 := func(v int) {
		buf[i] = byte('0' + v/10)
		buf[i+1] = byte('0' + v%10)
		i += 2
	}

	year := t.Year()
	buf[i+0] = byte('0' + (year/1000)%10)
	buf[i+1] = byte('0' + (year/100)%10)
	buf[i+2] = byte('0' + (year/10)%10)
	buf[i+3] = byte('0' + year%10)
	i += 4
	put2(int(t.Month()))
	put2(t.Day())
	put2(t.Hour())
	put2(t.Minute())
	put2(t.Second())

	// optional fractional seconds (µs precision)
	nsec := t.Nanosecond()
	if nsec != 0 {
		frac := nsec / 1_000 // to microseconds (max 6 digits)
		buf[i] = '.'
		i++
		start := i
		// write six digits, then trim trailing zeros later
		for p := 100_000; p >= 1; p /= 10 {
			buf[i] = byte('0' + (frac/p)%10)
			i++
		}
		// trim right-hand zeros
		for i > start && buf[i-1] == '0' {
			i--
		}
	}

	buf[i] = 'Z'
	i++

	return string(buf[:i])
}

func decGeneralizedTime(b []byte) (GeneralizedTime, error) {
	t, err := parseGeneralizedTime(string(b))
	return GeneralizedTime(t), err
}

func encGeneralizedTime(d GeneralizedTime) ([]byte, error) {
	return []byte(formatGeneralizedTime(time.Time(d))), nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralizedTime) String() string { return formatGeneralizedTime(r.Cast()) }

/*
Layout returns the string literal "20060102150405". Note that the
terminating Zulu character (Z) is not included, as it is not used
wherever a UTC offset value is desired (e.g.: -0700).
*/
func (r GeneralizedTime) Layout() string { return genTimeLayout }

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r GeneralizedTime) Cast() time.Time { return time.Time(r) }

/*
Eq returns a Boolean value indicative of r being equal to t.
*/
func (r GeneralizedTime) Eq(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Equal(in)
}

/*
Ne returns a Boolean value indicative of r not being equal to t.
*/
func (r GeneralizedTime) Ne(t Temporal) bool {
	in := truncateBy(t, t)
	return !r.Cast().Equal(in)
}

/*
Lt returns a Boolean value indicative of r occurring before t.
*/
func (r GeneralizedTime) Lt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().Before(in)
}

/*
Le returns a Boolean value indicative of r occurring before, or at the same time as, t.
*/
func (r GeneralizedTime) Le(t Temporal) bool { return r.Lt(t) || r.Eq(t) }

/*
Gt returns a Boolean value indicative of r occurring after t.
*/
func (r GeneralizedTime) Gt(t Temporal) bool {
	in := truncateBy(t, t)
	return r.Cast().After(in)
}

/*
Ge returns a Boolean value indicative of r occurring after, or at the same time as, t.
*/
func (r GeneralizedTime) Ge(t Temporal) bool { return r.Gt(t) || r.Eq(t) }

func chopZulu(raw string) string {
	if zulu := raw[len(raw)-1] == 'Z'; zulu {
		raw = raw[:len(raw)-1]
	}

	return raw
}

type temporalCodec[T Temporal] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup[Temporal]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *temporalCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdTemporalWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdTemporalWrite[T Temporal](c *temporalCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if wire, err = c.encodeHook(c.val); err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *temporalCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdTemporalRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdTemporalRead[T Temporal](c *temporalCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {
		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out T
			if out, err = c.decodeHook(wire); err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = out
					pkt.AddOffset(tlv.Length)
				}
			}
		}
	}

	return err
}

func (c *temporalCodec[T]) Tag() int          { return c.tag }
func (c *temporalCodec[T]) IsPrimitive() bool { return true }
func (c *temporalCodec[T]) String() string    { return "temporalCodec" }
func (c *temporalCodec[T]) getVal() any       { return c.val }
func (c *temporalCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

/*
RegisterTemporalAlias registers a custom alias of a [Temporal] qualifier
type for use in codec operations.

	// Create a custom type called Deadline.
	type Deadline GeneralizedTime

	// Be sure to implement the Primitive interface by
	// creating the three methods shown below: Tag,
	// String and IsPrimitive.

	func (r Deadline) Tag() int { return whateverTag }
	func (r Deadline) String string { return theStringRepresentation }
	func (r Deadline) IsPrimitive() bool { return true }
	// other methods if desired ...

	RegisterTemporalAlias[Deadline](whateverTag, nil, nil, nil, nil) // use default codec

	var dead Deadline
	// populate Deadline timestamp as desired

	pkt, err := Marshal(lease, With(DER))
	if err != nil {
	   fmt.Println(err)
	   return
	}

	// ... etc ...
*/
func RegisterTemporalAlias[T Temporal](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint[Temporal],
	user ...Constraint[Temporal],
) {
	all := append(ConstraintGroup[Temporal]{spec}, user...)

	encoder, decoder = fillTemporalHooks[T](encoder, decoder)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &temporalCodec[T]{
				tag:          tag,
				cg:           all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder,
			}
		},
		newWith: func(v any) box {
			return &temporalCodec[T]{
				val:          valueOf[T](v),
				tag:          tag,
				cg:           all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder,
			}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func attachDefaults[Canon any, T Temporal](
	rt reflect.Type,
	enc *EncodeOverride[T],
	dec *DecodeOverride[T],
	canonEnc EncodeOverride[Canon],
	canonDec DecodeOverride[Canon],
) bool {
	canonRT := refTypeOf((*Canon)(nil)).Elem()

	// match ONLY the identical canonical type
	if rt != canonRT {
		return false
	}

	// wrap encoder if the caller left it nil
	if *enc == nil {
		*enc = func(v T) ([]byte, error) {
			return canonEnc(any(v).(Canon))
		}
	}
	// wrap decoder if the caller left it nil
	if *dec == nil {
		*dec = func(b []byte) (T, error) {
			var cVal any
			var val T
			var err error
			if cVal, err = canonDec(b); err == nil {
				val = any(cVal).(T)
			}
			return val, err
		}
	}
	return true
}

type durationCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup[T]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *durationCodec[T]) Tag() int          { return c.tag }
func (c *durationCodec[T]) IsPrimitive() bool { return true }
func (c *durationCodec[T]) String() string    { return "durationCodec" }
func (c *durationCodec[T]) getVal() any       { return c.val }
func (c *durationCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func toDuration[T any](v T) Duration   { return *(*Duration)(unsafe.Pointer(&v)) }
func fromDuration[T any](d Duration) T { return *(*T)(unsafe.Pointer(&d)) }

func (c *durationCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdDurationWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdDurationWrite[T any](c *durationCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			wire = []byte(toDuration(c.val).String())
		}

		if err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *durationCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdDurationRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdDurationRead[T any](c *durationCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {
		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out T
			if c.decodeHook != nil {
				out, err = c.decodeHook(wire)
			} else {
				var (
					datePart string = string(wire)
					timePart string
				)
				if idx := idxr(string(wire), 'T'); idx != -1 {
					datePart = string(wire)[:idx]
					timePart = string(wire)[idx+1:]
				}

				var dur Duration
				if err = dur.parseDuration(datePart, timePart); err == nil {
					out = fromDuration[T](dur)
				}
			}

			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = out
					pkt.AddOffset(tlv.Length)
				}
			}
		}
	}

	return err
}

/*
RegisterDurationAlias registers a custom alias of [Duration] for use in codec operations.

	// Create a custom type called Lease.
	type Lease Duration

	// Be sure to implement the Primitive interface by
	// creating the three methods shown below: Tag,
	// String and IsPrimitive.

	func (r Lease) Tag() int { return whateverTag }
	func (r Lease) String string { return theStringRepresentation }
	func (r Lease) IsPrimitive() bool { return true }
	// other methods if desired ...

	RegisterDurationAlias[Lease](whateverTag, nil, nil, nil, nil) // use default codec

	var lease Duration
	// populate Duration struct as needed

	pkt, err := Marshal(lease, With(DER))
	if err != nil {
	   fmt.Println(err)
	   return
	}

	// ... etc ...
*/
func RegisterDurationAlias[T any](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint[T],
	user ...Constraint[T],
) {
	all := append(ConstraintGroup[T]{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &durationCodec[T]{
				tag:          tag,
				cg:           all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder,
			}
		},
		newWith: func(v any) box {
			return &durationCodec[T]{
				val:          valueOf[T](v),
				tag:          tag,
				cg:           all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder,
			}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterTemporalAlias[Date](TagDate,
		DateConstraintPhase,
		nil, nil, nil, nil)
	RegisterTemporalAlias[DateTime](TagDateTime,
		DateTimeConstraintPhase,
		nil, nil, nil, nil)
	RegisterTemporalAlias[TimeOfDay](TagTimeOfDay,
		TimeOfDayConstraintPhase,
		nil, nil, nil, nil)
	RegisterTemporalAlias[GeneralizedTime](TagGeneralizedTime,
		GeneralizedTimeConstraintPhase,
		nil, nil, nil, nil)
	RegisterTemporalAlias[Time](TagTime,
		TimeConstraintPhase,
		nil, nil, nil, nil)
	RegisterDurationAlias[Duration](TagDuration,
		DurationConstraintPhase,
		nil, nil, nil, nil)
}
