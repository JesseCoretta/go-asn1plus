package asn1plus

/*
time.go implements all temporal syntaxes and matching rules -- namely
those for Generalized Time and the (deprecated) UTC Time.
*/

import (
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
		err = mkerr("Invalid type for ASN.1 DATE")
	}

	var t time.Time
	if err == nil {
		t, err = parseDate(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Validate(Date(t))
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

func (r Date) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *Date) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for DATE decoding")
	}

	return
}

func (r *Date) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var t time.Time
			if t, err = parseDate(string(data)); err == nil {
				*r = Date(t)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}

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
		err = mkerr("Invalid type for ASN.1 DATE-TIME")
	}

	var t time.Time
	if err == nil {
		t, err = parseDateTime(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Validate(DateTime(t))
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

func (r DateTime) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *DateTime) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for DATE-TIME decoding")
	}

	return
}

func (r *DateTime) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var t time.Time
			if t, err = parseDateTime(string(data)); err == nil {
				*r = DateTime(t)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
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
		err = mkerr("Invalid type for ASN.1 TIME-OF-DAY")
	}

	var t time.Time
	if err == nil {
		t, err = parseTimeOfDay(s)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Temporal] = constraints
		err = group.Validate(TimeOfDay(t))
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

func (r TimeOfDay) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *TimeOfDay) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for TIME-OF-DAY decoding")
	}

	return
}

func (r *TimeOfDay) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var t time.Time
			if t, err = parseTimeOfDay(string(data)); err == nil {
				*r = TimeOfDay(t)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}

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
		return Duration{}, mkerr("Invalid type for ASN.1 DURATION")
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

	// Helper to parse a numeric value ending with a given suffix.
	parseNumber := func(str string, suffix byte) (float64, string, error) {
		idx := stridxb(str, suffix)
		if idx < 0 {
			return 0, str, mkerr("expected suffix " + string(suffix) + " not found in " + str)
		}
		numStr := str[:idx]
		// Replace comma with dot if necessary.
		numStr = replace(numStr, ",", ".", 1)
		num, err := pfloat(numStr, 64)
		if err != nil {
			return 0, str, mkerr("error parsing number " + numStr + ": " + err.Error())
		}
		return num, str[idx+1:], nil
	}

	// Parse the date portion for Years, Months, Days.
	if err = _r.marshalYMD(datePart, parseNumber); err == nil {
		err = _r.marshalHMS(timePart, parseNumber)
	}

	err = checkDurationEmpty(_r, err)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Duration] = constraints
		err = group.Validate(_r)
	}

	var r Duration
	if err == nil {
		r = _r
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

// LessThan returns true if d is strictly less than other.
func (r Duration) LessThan(other Duration) bool {
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

func (r Duration) AddTo(ref time.Time) time.Time {
	t := ref.AddDate(r.Years, r.Months, r.Days)
	additional := time.Duration(r.Hours)*time.Hour +
		time.Duration(r.Minutes)*time.Minute +
		time.Duration(r.Seconds*float64(time.Second))
	return t.Add(additional)
}

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

func (r Duration) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *Duration) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for Duration decoding")
	}

	return
}

func (r *Duration) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var dur Duration
			if dur, err = NewDuration(string(data)); err == nil {
				*r = dur
			}
			pkt.SetOffset(pkt.Offset() + tlv.Length)
		}
	}

	return
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
		return gt, mkerr("Invalid type for ASN.1 GENERALIZED TIME")
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
		err = group.Validate(GeneralizedTime(t))
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

	loc, i, err := parseGTTimezone(s, i)
	if err != nil {
		return time.Time{}, err
	}
	if i != len(s) {
		return time.Time{}, mkerr("Invalid ASN.1 GENERALIZED TIME")
	}
	return time.Date(year, time.Month(mon), day, hr, min, sec, nsec, loc), nil
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

	// optional fractional seconds (µs precision) ---------------------------
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

func (r GeneralizedTime) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *GeneralizedTime) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for GENERALIZED TIME decoding")
	}

	return
}

func (r *GeneralizedTime) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var gt time.Time
			// TODO - adjust for UTC offset potential
			if gt, err = parseGeneralizedTime(string(data)); err == nil {
				*r = GeneralizedTime(gt)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
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
		err = mkerr("Invalid type for ASN.1 UTC Time")
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
		err = group.Validate(UTCTime(_utc))
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

	hasSec := utcDigit(s[10])
	if hasSec && len(s) < 13 {
		err = mkerr("Invalid ASN.1 UTC TIME")
		return
	}
	if hasSec && !utcDigit(s[11]) {
		err = mkerr("Invalid ASN.1 UTC TIME")
		return
	}

	yy = utcToInt(s[0], s[1])
	mm = utcToInt(s[2], s[3])
	dd = utcToInt(s[4], s[5])
	hr = utcToInt(s[6], s[7])
	mn = utcToInt(s[8], s[9])
	sc = 0
	next = 10

	if hasSec {
		sc = utcToInt(s[10], s[11])
		next = 12
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

func parseUTCTime(s string) (time.Time, error) {
	yy, mo, dd, hr, mn, sc, i, err := parseUTCCore(s)
	if err != nil {
		return time.Time{}, err
	}

	loc, err := parseUTCTimezone(s, i)
	if err != nil {
		return time.Time{}, err
	}

	// two-digit year mapping (50-99 ⇒ 19xx, 00-49 ⇒ 20xx)
	if yy < 50 {
		yy += 2000
	} else {
		yy += 1900
	}

	return time.Date(yy, time.Month(mo), dd, hr, mn, sc, 0, loc), nil
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

func (r UTCTime) write(pkt Packet, opts Options) (n int, err error) {
	str := r.String()
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(str), false, []byte(str)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *UTCTime) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for UTCTime decoding")
	}

	return
}

func (r *UTCTime) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			var gt time.Time
			if gt, err = parseUTCTime(string(data)); err == nil {
				*r = UTCTime(gt)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}
