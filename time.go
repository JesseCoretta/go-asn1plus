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

/*
Temporal is a date and time interface qualified by instances of the
following types:

  - [Time]
  - [Date]
  - [DateTime]
  - [TimeOfDay]
  - [GeneralizedTime]
  - [UTCTime]

Note that [Duration] does not qualify this interface.
*/
type Temporal interface {
	Cast() time.Time
	String() string
}

const (
	dateLayout      = "2006-01-02"
	dateTimeLayout  = "2006-01-02T15:04:05"
	timeOfDayLayout = "15:04:05"
	genTimeLayout   = "20060102150405"
	utcTimeLayout   = "0601021504"
)

/*
Time implements the base ASN.1 TIME (tag 14) which underlies the following
types:

  - [Date]
  - [DateTime]
  - [TimeOfDay]
*/
type Time time.Time

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
Date implements the ASN.1 DATE type (tag 31), which extends from [Time].
*/
type Date Time

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

// parseDate parses YYYY-MM-DD in UTC, no heap, ~70 ns.
func parseDate(s string) (time.Time, error) {
	if len(s) != 10 {
		return time.Time{}, mkerr("Invalid ASN.1 DATE length")
	}
	if s[4] != '-' || s[7] != '-' {
		return time.Time{}, mkerr("Invalid ASN.1 DATE format")
	}
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }

	year := toInt(s[0], s[1])*100 + toInt(s[2], s[3])
	month := toInt(s[5], s[6])
	day := toInt(s[8], s[9])

	if month == 0 || month > 12 || day == 0 || day > 31 {
		return time.Time{}, mkerr("Invalid ASN.1 DATE value")
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
		return time.Time{}, mkerr("Invalid DATE-TIME length")
	}
	// quick layout check – cheap and rejects most garbage early
	if s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return time.Time{}, mkerr("Invalid DATE-TIME format")
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
TimeOfDay implements the ASN.1 TIME-OF-DAY type (tag 32), which extends from [Time].
*/
type TimeOfDay Time

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
		return time.Time{}, mkerr("Invalid ASN.1 TIME-OF-DAY length")
	}
	if s[2] != ':' || s[5] != ':' {
		return time.Time{}, mkerr("Invalid ASN.1 TIME-OF-DAY format")
	}
	toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') } // ASCII

	hh := toInt(s[0], s[1])
	mm := toInt(s[3], s[4])
	ss := toInt(s[6], s[7])
	if hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, mkerr("Invalid ASN.1 TIME-OF-DAY value")
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
TimeOfDay implements the ASN.1 DURATION type (tag 34).
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
		return Duration{}, mkerr("duration must start with 'P'")
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
		err = mkerr("ASN.1 DURATION must contain at least one component")
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
		/*
			// COVERAGE: unreachable
			if idx < 0 {
				return 0, str, mkerrf("expected suffix ", string(suffix), " not found in ", str)
			}
		*/
		numStr := str[:idx]
		// Replace comma with dot if necessary.
		numStr = replace(numStr, ",", ".", 1)
		num, err := pfloat(numStr, 64)
		if err != nil {
			return 0, str, mkerrf("error parsing number ", numStr, ": ", err.Error())
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
Lt returns true if d is strictly less than other.
*/
func (r Duration) Lt(other Duration) bool {
	if r.Years != other.Years {
		return r.Years < other.Years
	}
	if r.Months != other.Months {
		return r.Months < other.Months
	}
	if r.Days != other.Days {
		return r.Days < other.Days
	}
	if r.Hours != other.Hours {
		return r.Hours < other.Hours
	}
	if r.Minutes != other.Minutes {
		return r.Minutes < other.Minutes
	}
	return r.Seconds < other.Seconds
}

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
			return gt, mkerr("Invalid ASN.1 GENERALIZED TIME")
		}
		raw = tv
	default:
		return gt, errorBadTypeForConstructor("GENERALIZED TIME", x)
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
				err = mkerr(`Fraction exceeds Generalized Time fractional limit`)
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
		err = mkerr("Invalid ASN.1 GENERALIZED TIME")
		return
	}
	for k := 0; k < 14; k++ {
		if !digit(s[k]) {
			err = mkerr("Invalid ASN.1 GENERALIZED TIME")
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
		err = mkerr("Fraction exceeds Generalized Time fractional limit")
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
		err = mkerr("Invalid ASN.1 GENERALIZED TIME")
		return
	}
	switch s[next] {
	case 'Z':
		if next != len(s)-1 {
			err = mkerr("Invalid ASN.1 GENERALIZED TIME")
			return
		}
		loc = time.UTC
		next++
	case '+', '-':
		if next+5 != len(s) {
			err = mkerr("Invalid ASN.1 GENERALIZED TIME")
			return
		}
		for k := 1; k <= 4; k++ {
			if !digit(s[next+k]) {
				err = mkerr("Invalid ASN.1 GENERALIZED TIME")
				return
			}
		}
		toInt := func(b0, b1 byte) int { return int(b0-'0')*10 + int(b1-'0') }
		hh, mm := toInt(s[next+1], s[next+2]), toInt(s[next+3], s[next+4])
		if hh > 23 || mm > 59 {
			err = mkerr("Invalid ASN.1 GENERALIZED TIME")
			return
		}
		off := (hh*60 + mm) * 60
		if s[next] == '-' {
			off = -off
		}
		loc = time.FixedZone("", off)
		next += 5
	default:
		err = mkerr("Invalid ASN.1 GENERALIZED TIME")
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

	/*
		// COVERAGE: unreachable
		if i != len(s) {
			return time.Time{}, mkerr("Invalid ASN.1 GENERALIZED TIME")
		}
	*/

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
func (r GeneralizedTime) Layout() string {
	return genTimeLayout
}

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r GeneralizedTime) Cast() time.Time {
	return time.Time(r)
}

/*
Deprecated: UTCTime aliases an instance of [time.Time] to implement the
obsolete ASN.1 UTC TIME (tag 23)

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type UTCTime Time

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
func (r UTCTime) Layout() string { return utcTimeLayout }

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r UTCTime) Cast() time.Time { return time.Time(r) }

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

func chopZulu(raw string) string {
	if zulu := raw[len(raw)-1] == 'Z'; zulu {
		raw = raw[:len(raw)-1]
	}

	return raw
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

type temporalCodec[T Temporal] struct {
	val T
	tag int
	cg  ConstraintGroup[Temporal]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *temporalCodec[T]) write(pkt Packet, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdTemporalWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdTemporalWrite[T Temporal](c *temporalCodec[T], pkt Packet, o *Options) (off int, err error) {
	o = deferImplicit(o)

	if err = c.cg.Constrain(c.val); err == nil {
		var wire []byte
		if wire, err = c.encodeHook(c.val); err == nil {
			tag, cls := effectiveTag(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *temporalCodec[T]) read(pkt Packet, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdTemporalRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdTemporalRead[T Temporal](c *temporalCodec[T], pkt Packet, tlv TLV, o *Options) error {
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
				if err = c.cg.Constrain(out); err == nil {
					c.val = out
					pkt.SetOffset(pkt.Offset() + tlv.Length)
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
	default:
		panic("RegisterTemporalAlias: please provide encode/decode hooks for custom temporal type")
	}

	return enc, dec
}

type durationCodec[T any] struct {
	val T
	tag int
	cg  ConstraintGroup[T]

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

func (c *durationCodec[T]) write(pkt Packet, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdDurationWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdDurationWrite[T any](c *durationCodec[T], pkt Packet, o *Options) (off int, err error) {
	o = deferImplicit(o)

	if err = c.cg.Constrain(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			wire = []byte(toDuration(c.val).String())
		}

		if err == nil {
			tag, cls := effectiveTag(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *durationCodec[T]) read(pkt Packet, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdDurationRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdDurationRead[T any](c *durationCodec[T], pkt Packet, tlv TLV, o *Options) error {
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
				if err = c.cg.Constrain(out); err == nil {
					c.val = out
					pkt.SetOffset(pkt.Offset() + tlv.Length)
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
	RegisterTemporalAlias[Date](TagDate, nil, nil, nil, nil)
	RegisterTemporalAlias[DateTime](TagDateTime, nil, nil, nil, nil)
	RegisterTemporalAlias[TimeOfDay](TagTimeOfDay, nil, nil, nil, nil)
	RegisterTemporalAlias[GeneralizedTime](TagGeneralizedTime, nil, nil, nil, nil)
	RegisterTemporalAlias[UTCTime](TagUTCTime, nil, nil, nil, nil)
	RegisterDurationAlias[Duration](TagDuration, nil, nil, nil, nil)
}
