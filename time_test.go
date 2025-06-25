package asn1plus

import (
	"fmt"
	"testing"
	"time"
)

func ExampleTime_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewTime(`2014-12-31T08:04:55`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	// Here, we use the DateTime format for Time, though another
	// format could also apply.
	_, err := NewTime(`2015-04-19T15:43:08`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleDate_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewDate(`2014-12-31`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	_, err := NewDate(`2015-04-19`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleDateTime_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewDateTime(`2014-12-31T23:59:59`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	_, err := NewDateTime(`2015-04-19T13:44:13`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleTimeOfDay_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewTimeOfDay(`20:30:00`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	_, err := NewTimeOfDay(`22:44:13`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleGeneralizedTime_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewGeneralizedTime(`20141231110451Z`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	_, err := NewGeneralizedTime(`20250620171207Z`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleUTCTime_withConstraint() {
	deadlineConstraint := LiftConstraint(func(o Temporal) Temporal { return o },
		func(o Temporal) (err error) {
			deadline, _ := NewUTCTime(`6810310904Z`)
			if o.Cast().After(deadline.Cast()) {
				err = fmt.Errorf("Constraint violation: you're late!")
			}
			return
		})

	_, err := NewUTCTime(`9104051614Z`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func TestDuration_customType(t *testing.T) {
	type CustomDur Duration
	RegisterDurationAlias[CustomDur](TagDuration, nil, nil, nil, nil)

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	orig, _ := NewDuration(time.Duration(time.Second * 50))
	cust := CustomDur(orig)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out CustomDur
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	// We cheat again, since we didn't write a
	// custom OID method for this simple test.
	cast1 := Duration(orig).String()
	cast2 := Duration(cust).String()
	if cast1 != cast2 {
		t.Fatalf("%s failed [BER Duration cmp.]:\n\twant: %s\n\tgot:  %s",
			t.Name(), cast1, cast2)
	}
}

/*
This example demonstrates encoding and decoding an ASN.1 DATE
(2021-09-18) to/from a simple Go string.

	1F 1F  0A  32 30 32 31 2D 30 39 2D 31 38
	│  │   │   └─────────────── "2021-09-18" ───────────────┘
	│  │   └── length = 10
	└──┴────────── tag = UNIVERSAL 31 (DATE)
*/
func ExampleDate_viaGoString() {
	opts := Options{Identifier: "date"}

	pkt, err := Marshal(`2021-09-18`,
		With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Packet hex: %s\n", pkt.Hex())

	var date string
	if err = Unmarshal(pkt, &date, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Date: %s\n", date)

	// Output:
	// Packet hex: 1F1F 0A 323032312D30392D3138
	// Date: 2021-09-18
}

func ExampleTimeOfDay_viaGoString() {
	opts := Options{Identifier: "time-of-day"}

	pkt, err := Marshal(`15:32:01`, With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Packet hex: %s\n", pkt.Hex())

	var tod string
	if err = Unmarshal(pkt, &tod, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Time: %s\n", tod)

	// Output:
	// Packet hex: 1F20 08 31353A33323A3031
	// Time: 15:32:01
}

func ExampleTime_viaGoString() {
	opts := Options{Identifier: "time"}

	pkt, err := Marshal(`2018-09-11T15:32:01`, With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Packet hex: %s\n", pkt.Hex())

	var thyme string
	if err = Unmarshal(pkt, &thyme, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Time: %s\n", thyme)

	// Output:
	// Packet hex: 0E 13 323031382D30392D31315431353A33323A3031
	// Time: 2018-09-11T15:32:01
}

func ExampleDuration_AddTo() {
	d1, err := NewDuration("P1Y2M3DT4H5M30S")
	if err != nil {
		fmt.Println("Duration error:", err)
		return
	}
	gt, _ := time.Parse("20060102150405", "20250401150307")
	t := d1.AddTo(gt)
	fmt.Printf("Time %s", t)
	// Output: Time 2026-06-04 19:08:37 +0000 UTC
}

func ExampleDuration_Duration() {
	d1, err := NewDuration("P1Y2M3DT4H5M30S")
	if err != nil {
		fmt.Println("Duration error:", err)
		return
	}
	dur := d1.Duration()
	fmt.Printf("%T: %s", dur, dur)
	// Output: time.Duration: 10276h5m30s
}

func ExampleDuration_secondsMustBe30() {
	// Define a constraint that forces the seconds component to equal 30.
	secondsMustBe30 := DurationComponentConstraint(func(d Duration) error {
		if d.Seconds != 30 {
			return fmt.Errorf("seconds component %v is not equal to 30", d.Seconds)
		}
		return nil
	})

	// Parse a duration that should pass.
	d1, err := NewDuration("P1Y2M3DT4H5M30S")
	if err != nil {
		fmt.Println("Duration error:", err)
		return
	}
	if err := secondsMustBe30(d1); err != nil {
		fmt.Printf("duration %v fails: %v\n", d1.String(), err)
	} else {
		fmt.Printf("duration %v passes secondsMustBe30\n", d1.String())
	}

	// Parse a duration that should fail.
	d2, err := NewDuration("P1Y2M3DT4H5M45S")
	if err != nil {
		fmt.Println("Duration error:", err)
		return
	}
	if err := secondsMustBe30(d2); err != nil {
		fmt.Printf("duration %v fails: %v\n", d2.String(), err)
	} else {
		fmt.Printf("duration %v passes secondsMustBe30\n", d2.String())
	}

	// Output:
	// duration P1Y2M3DT4H5M30S passes secondsMustBe30
	// duration P1Y2M3DT4H5M45S fails: seconds component 45 is not equal to 30
}

func ExampleDate_weekendConstraint() {
	// Define a weekend property constraint for Date.
	weekend := PropertyConstraint(func(d Date) error {
		// Use the underlying time.Time to check the weekday.
		weekday := time.Time(d).Weekday()
		if weekday != time.Saturday && weekday != time.Sunday {
			return fmt.Errorf("date %v does not fall on a weekend", d)
		}
		return nil
	})

	// Parse a date that is a weekend:
	d1, err := NewDate("2021-09-18") // 18 September 2021 is a Saturday.
	if err != nil {
		fmt.Println("ParseDate error:", err)
		return
	}
	if err := weekend(d1); err != nil {
		fmt.Printf("%v is not a weekend: %v\n", d1, err)
	} else {
		fmt.Printf("%v is a weekend\n", d1)
	}

	// Parse a date that is a weekday:
	d2, err := NewDate("2021-09-15") // 15 September 2021 is a Wednesday.
	if err != nil {
		fmt.Println("ParseDate error:", err)
		return
	}
	if err := weekend(d2); err != nil {
		fmt.Printf("%v is not a weekend: %v\n", d2, err)
	} else {
		fmt.Printf("%v is a weekend\n", d2)
	}

	// Output:
	// 2021-09-18 is a weekend
	// 2021-09-15 is not a weekend: date 2021-09-15 does not fall on a weekend
}

func ExampleDate() {
	d, err := NewDate("1636-09-18")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(d.String())
	// Output:
	// 1636-09-18
}

func ExampleDateTime() {
	dt, err := NewDateTime("2000-11-22T18:30:23")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(dt.String())
	// Output:
	// 2000-11-22T18:30:23
}

func ExampleTimeOfDay() {
	// Without fractional seconds.
	t1, err := NewTimeOfDay("18:30:23")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(t1.String())

	// With fractional seconds (using a comma).
	t2, err := NewTimeOfDay("15:27:35")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(t2.String())
	// Output:
	// 18:30:23
	// 15:27:35
}

func ExampleDuration() {
	// Example without fractional seconds.
	dur, err := NewDuration("P2Y10M15DT10H20M30S")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(dur.String())

	// Example with fractional seconds.
	dur2, err := NewDuration("P1Y2M3DT4H5M6,7S")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Note: The formatting rounds fractional seconds, so 6,7 becomes 7.
	fmt.Println(dur2.String())
	// Output:
	// P2Y10M15DT10H20M30S
	// P1Y2M3DT4H5M7S
}

func ExampleGeneralizedTime_dER() {
	// Parse time string into GeneralizedTime instance
	gt, err := NewGeneralizedTime(`20250525050201Z`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode the GeneralizedTime instance
	var pkt Packet
	if pkt, err = Marshal(gt); err != nil {
		fmt.Println(err)
		return
	}

	// Decode the DER Packet into new GeneralizedTime instance
	var gt2 GeneralizedTime
	if err = Unmarshal(pkt, &gt2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", gt, gt.String() == gt2.String(), gt2)
	// Output: asn1plus.GeneralizedTime values match: true (20250525050201Z)
}

func ExampleUTCTime_dER() {
	// Parse time string into UTCTime instance
	ut, err := NewUTCTime(`9805061703Z`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode the UTCTime instance
	var pkt Packet
	if pkt, err = Marshal(ut); err != nil {
		fmt.Println(err)
		return
	}

	// Decode the DER Packet into new UTCTime instance
	var ut2 UTCTime
	if err = Unmarshal(pkt, &ut2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", ut, ut.String() == ut2.String(), ut2)
	// Output: asn1plus.UTCTime values match: true (9805061703Z)
}

func TestNewDuration_validInputs(t *testing.T) {
	for _, in := range []any{
		"P1Y2M3DT4H5M6S",                // string
		[]byte("P2DT12H"),               // []byte
		time.Duration(90 * time.Minute), // time.Duration
	} {
		if _, err := NewDuration(in, DurationRangeConstraint(Duration{}, Duration{Years: 9})); err != nil {
			t.Errorf("NewDuration(%#v) returned error: %v", in, err)
		}
	}
}

func TestNewDuration_invalidInputs(t *testing.T) {
	for _, in := range []any{
		"X1Y",        // string not starting with 'P'
		[]byte("PT"), // missing number
		12345,        // unsupported type
	} {
		if _, err := NewDuration(in); err == nil {
			t.Errorf("expected error for input %#v; got nil", in)
		}
	}
}

func TestNewDuration_constraintViolation(t *testing.T) {
	tooBig := "P20Y" // 20 years, well above maxDur
	if _, err := NewDuration(tooBig, DurationRangeConstraint(Duration{}, Duration{Years: 9})); err == nil {
		t.Fatalf("expected range-constraint error for %q, got nil", tooBig)
	}
}

func TestGeneralizedTime_encodingRules(t *testing.T) {
	for _, value := range []any{
		`20250525050201Z`,
	} {
		for _, rule := range encodingRules {
			gt, err := NewGeneralizedTime(value)
			if err != nil {
				t.Fatalf("%s[%s] failed: %v\n", t.Name(), rule, err)
			}
			gt.IsPrimitive()
			gt.Tag()
			_ = gt.String()

			var pkt Packet
			if pkt, err = Marshal(gt, With(rule)); err != nil {
				t.Fatalf("%s[%s encoding] failed: %v\n", t.Name(), rule, err)
			}

			var gt2 GeneralizedTime
			if err = Unmarshal(pkt, &gt2); err != nil {
				t.Fatalf("%s[%s decoding] failed: %v\n", t.Name(), rule, err)
			}
		}
	}
}

func TestUTCTime_encodingRules(t *testing.T) {
	for _, value := range []any{
		`9805061703Z`,
	} {
		for _, rule := range encodingRules {
			gt, err := NewUTCTime(value)
			if err != nil {
				t.Fatalf("%s[%s] failed: %v\n", t.Name(), rule, err)
			}
			gt.IsPrimitive()
			gt.Tag()
			_ = gt.String()

			var pkt Packet
			if pkt, err = Marshal(gt, With(rule)); err != nil {
				t.Fatalf("%s[%s encoding] failed: %v\n", t.Name(), rule, err)
			}

			var gt2 UTCTime
			if err = Unmarshal(pkt, &gt2); err != nil {
				t.Fatalf("%s[%s decoding] failed: %v\n", t.Name(), rule, err)
			}
		}
	}
}

func TestDateTime_encodingRules(t *testing.T) {
	dateTime, _ := time.Parse(dateTimeLayout, "2025-02-19T20:21:09")

	_, _ = NewDateTime(struct{}{})

	for idx, value := range []any{
		`2025-02-19T20:21:09`,
		[]byte(`2025-02-19T20:21:09`),
		dateTime,
		DateTime(dateTime),
	} {
		for _, rule := range encodingRules {
			gt, err := NewDateTime(value)
			if err != nil {
				t.Fatalf("%s[%s][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			gt.IsPrimitive()
			gt.Tag()
			_ = gt.String()

			var pkt Packet
			if pkt, err = Marshal(gt, With(rule)); err != nil {
				t.Fatalf("%s[%s encoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			var gt2 DateTime
			if err = Unmarshal(pkt, &gt2); err != nil {
				t.Fatalf("%s[%s decoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}
		}
	}
}

func TestTimeOfDay_encodingRules(t *testing.T) {
	timeOfDay, _ := time.Parse(timeOfDayLayout, "20:21:09")

	_, _ = NewTimeOfDay(struct{}{})

	for idx, value := range []any{
		`20:21:09`,
		[]byte(`20:21:09`),
		timeOfDay,
		TimeOfDay(timeOfDay),
	} {
		for _, rule := range encodingRules {
			gt, err := NewTimeOfDay(value)
			if err != nil {
				t.Fatalf("%s[%s][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			gt.IsPrimitive()
			gt.Tag()
			_ = gt.String()

			var pkt Packet
			if pkt, err = Marshal(gt, With(rule)); err != nil {
				t.Fatalf("%s[%s encoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			var gt2 TimeOfDay
			if err = Unmarshal(pkt, &gt2); err != nil {
				t.Fatalf("%s[%s decoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}
		}
	}
}

func TestDate_encodingRules(t *testing.T) {
	date, _ := time.Parse(dateLayout, "2025-02-19")

	_, _ = NewDate(struct{}{})

	for idx, value := range []any{
		`2025-02-19`,
		[]byte(`2025-02-19`),
		date,
		Date(date),
	} {
		for _, rule := range encodingRules {
			gt, err := NewDate(value)
			if err != nil {
				t.Fatalf("%s[%s][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			gt.IsPrimitive()
			gt.Tag()
			_ = gt.String()

			var pkt Packet
			if pkt, err = Marshal(gt, With(rule)); err != nil {
				t.Fatalf("%s[%s encoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}

			var gt2 Date
			if err = Unmarshal(pkt, &gt2); err != nil {
				t.Fatalf("%s[%s decoding][%d] failed: %v\n", t.Name(), rule, idx, err)
			}
		}
	}
}

func TestUTCTime(t *testing.T) {
	var u UTCTime
	u.Cast()
	u.Tag()

	var err error

	if _, err = NewUTCTime(`9911040404`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	if _, err = NewUTCTime(`9911040403`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	for idx, thyme := range []string{
		`9805061703Z`,
		`980506170306Z`,
		`620506170306-0500`,
	} {
		if utct, err := NewUTCTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = utct.String()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`98170306Z`,
	} {
		if _, err := NewUTCTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
		}
	}
}

func TestGeneralizedTime(t *testing.T) {
	for idx, thyme := range []string{
		`20240229155701.0Z`,
		`20240229155703.00Z`,
		`20240229155702.000Z`,
		`20240229155703.0000Z`,
		`20240229155703.00000Z`,
		`20240229155703.000000Z`,
		`19540426135103Z`,
		`20240229155703-0500`,
		`20240229155703.0-0700`,
		`20240229155703.00-0700`,
		`20240229155703.000+1100`,
		`20240229155703.0000-0200`,
		`20240229155703.00000-0800`,
		`20200629155703.000000-0100`,
	} {
		if thyme, err := NewGeneralizedTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = thyme.String()
			thyme.Cast()
			thyme.Tag()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`202402291550.0000000-0800`,
		`20241202183734.0000000-0700`,
	} {
		if _, err := NewGeneralizedTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		}
	}

	_, err := genTimeFracDiffFormat(`20241202183734Z`, `.00000000`, `-0700`, `20060102150405`)
	if err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
	}
}

func TestFormatGeneralizedTime_FractionalSeconds(t *testing.T) {
	cases := []struct {
		nanos    int
		expected string
	}{
		{999_999_000, ".999999"},
		{123_450_000, ".12345"},
		{100_000_000, ".1"},
		{1_000_000, ".001"},
		{1_000, ".000001"},
		{999_999_999, ".999999"}, // because only µs precision used
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("nanos=%d", tc.nanos), func(t *testing.T) {
			base := time.Date(2025, 6, 20, 15, 4, 5, tc.nanos, time.UTC)
			got := formatGeneralizedTime(base)
			suffix := tc.expected + "Z"
			if !hasSfx(got, suffix) {
				t.Errorf("expected suffix %q, got %q", suffix, got)
			}
		})
	}
}

func TestParseTimeDuration_NegativeDuration(t *testing.T) {
	// Example duration: -1 year, -2 months, -3 days, -4 hours, -5 minutes, -6.5 seconds
	td := -(year*time.Duration(1) +
		mon*time.Duration(2) +
		day*time.Duration(3) +
		4*time.Hour +
		5*time.Minute +
		time.Duration(6500)*time.Millisecond)

	d := parseTimeDuration(td)

	if d.Years != -1 || d.Months != -2 || d.Days != -3 ||
		d.Hours != -4 || d.Minutes != -5 || int(d.Seconds) != -6 {
		t.Errorf("parsed duration incorrect: %+v", d)
	}

	if d.Seconds > 0 {
		t.Errorf("expected negative seconds, got %v", d.Seconds)
	}
}

func TestDuration_Lt_FieldComparisons(t *testing.T) {
	base := Duration{
		Years:   1,
		Months:  2,
		Days:    3,
		Hours:   4,
		Minutes: 5,
		Seconds: 6.7,
	}

	cases := []struct {
		name     string
		other    Duration
		expected bool
	}{
		{
			name: "Different Months",
			other: Duration{
				Years:   1,
				Months:  3,
				Days:    3,
				Hours:   4,
				Minutes: 5,
				Seconds: 6.7,
			},
			expected: true,
		},
		{
			name: "Different Minutes",
			other: Duration{
				Years:   1,
				Months:  2,
				Days:    3,
				Hours:   4,
				Minutes: 6,
				Seconds: 6.7,
			},
			expected: true,
		},
		{
			name:     "Same Duration",
			other:    base,
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Lt(tc.other)
			if got != tc.expected {
				t.Errorf("%s: expected %v, got %v", tc.name, tc.expected, got)
			}
		})
	}
}

func TestParseNumber_MissingSuffix(t *testing.T) {
	parseNumber := func(str string, suffix byte) (float64, string, error) {
		idx := idxr(str, rune(suffix))
		if idx < 0 {
			return 0, str, fmt.Errorf("expected suffix %q not found in %q", suffix, str)
		}
		return 0, "", nil
	}

	_, _, err := parseNumber("123.45", 'X') // 'X' is not present
	if err == nil || !cntns(err.Error(), "expected suffix") {
		t.Errorf("expected missing suffix error, got: %v", err)
	}
}

func Test_UTCHandler_WithOffset(t *testing.T) {
	raw := "250101123045+0200"
	sec := "05"
	diff := "-0700"
	format := "0601021504"

	utc, err := uTCHandler(raw, sec, diff, format)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Time(utc).Hour() != 12 {
		t.Errorf("unexpected UTC hour: %v", utc)
	}
}

func Test_parseUTCCore_InvalidDigits(t *testing.T) {
	cases := []struct {
		input string
	}{
		{"25A1011230Z"},
		{"25010112A0Z"},
		{"25010112304X"},
		{"25010112304X"},
		{"25010112307?"},
		{"970104123455Z"},
		{"9701041234554783957349Z"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			_, _, _, _, _, _, _, err := parseUTCCore(c.input)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", c.input)
			}
		})
	}
}

func Test_parseUTCTimezone_OffsetConstruction(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		idx      int
		expected int // offset in seconds
	}{
		{"PositiveOffset", "+0230", 0, (2*60 + 30) * 60},
		{"NegativeOffset", "-0500", 0, -(5 * 60 * 60)},
		{"MidnightOffset", "+0000", 0, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc, err := parseUTCTimezone(c.input, c.idx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if loc == nil || loc.String() != time.FixedZone("", c.expected).String() {
				t.Errorf("unexpected zone: got %v, want offset %d", loc, c.expected)
			}
		})
	}
}

func Test_parseUTCTime_ErrorsAndYearMapping(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantYear int
		wantErr  bool
	}{
		{"InvalidCore", "25010A1230Z", 0, true},   // parseUTCCore fails
		{"InvalidTZ", "2501011230X5", 0, true},    // parseUTCTimezone fails
		{"Year2000s", "2401011230Z", 2024, false}, // yy = 24 → 2024
		{"Year1900s", "7501011230Z", 1975, false}, // yy = 75 → 1975
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseUTCTime(c.input)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", c.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for input %q: %v", c.input, err)
				return
			}
			if got.Year() != c.wantYear {
				t.Errorf("expected year %d, got %d", c.wantYear, got.Year())
			}
		})
	}
}

func Test_parseUTCTimezone_InvalidCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		idx   int
	}{
		{"Empty input", "", 0},
		{"Z not at end", "Z123", 0},
		{"Offset too short", "+120", 0},
		{"Offset non-digit", "+1X00", 0},
		{"Offset overflow", "+2460", 0},
		{"Invalid indicator", "*0000", 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc, err := parseUTCTimezone(c.input, c.idx)
			if err == nil || loc != nil {
				t.Errorf("expected error for input %q at idx %d, got loc=%v, err=%v",
					c.input, c.idx, loc, err)
			}
		})
	}
}

func TestTemporal_codecov(_ *testing.T) {
	var t Time
	t.Tag()
	t.Cast()
	t.IsPrimitive()
	noww := time.Now()

	t.Eq(Date(noww))
	t.Ne(Time(noww))
	t.Ge(Time(noww))
	t.Gt(TimeOfDay(noww))
	t.Le(Time(noww))
	t.Lt(Time(noww))

	parseTime("2009-01-15")
	parseTime("9511041405")
	parseTime("01:15:07")
	parseTime("20090813081703")
	parseTime("20090813081703Z")
	NewTime([]byte("2017-01-04T15:04:39"))
	NewTime(time.Now())
	NewTime(Time(time.Now()))
	NewTime(struct{}{})
	fallbackTimeMatch("x")
	fallbackTimeMatch("2009-01-15")

	var d Date
	d.Tag()
	d.Cast()
	d.IsPrimitive()
	d.Layout()
	_, _ = parseDate(`1`)
	_, _ = parseDate(`2015?11=26`)
	_, _ = parseDate(`2015-13-36`)
	d.Eq(Date(noww))
	d.Ne(Date(noww))
	d.Ge(Date(noww))
	d.Gt(Date(noww))
	d.Le(Date(noww))
	d.Lt(Date(noww))

	var dt DateTime
	dt.Tag()
	dt.Cast()
	dt.IsPrimitive()
	dt.Layout()
	_, _ = parseDateTime(`1`)
	_, _ = parseDateTime(`2015?13-36T24:33:21`)
	_, _ = parseDateTime(`2015-13-36T14:33:21`)
	dt.Eq(DateTime(noww))
	dt.Ne(DateTime(noww))
	dt.Ge(DateTime(noww))
	dt.Gt(DateTime(noww))
	dt.Le(DateTime(noww))
	dt.Lt(DateTime(noww))

	var tod TimeOfDay
	tod.Tag()
	tod.Cast()
	tod.IsPrimitive()
	tod.Layout()
	_, _ = parseTimeOfDay(`1`)
	_, _ = parseTimeOfDay(`24?33=21`)
	_, _ = parseTimeOfDay(`24:53:21`)
	tod.Eq(TimeOfDay(noww))
	tod.Ne(TimeOfDay(noww))
	tod.Ge(TimeOfDay(noww))
	tod.Gt(TimeOfDay(noww))
	tod.Le(TimeOfDay(noww))
	tod.Lt(TimeOfDay(noww))

	var dur Duration
	dur.Tag()
	dur.IsPrimitive()
	NewDuration(`1`)
	NewDuration(`P1T1`)
	x, _ := NewDuration(`P1YM3DT4H5M30S`)
	y, _ := NewDuration(`P5YM3DT4H5M30S`)
	NewDuration(`PXYXMXDTXHXMXXS`)
	NewDuration(`PXYXMXDTXHXMXXS`)
	y.Eq(Duration{
		Years:   4,
		Months:  1,
		Days:    1,
		Hours:   13,
		Minutes: 8,
		Seconds: 31,
	})
	y.Ne(x)
	y.Ge(x)
	y.Gt(y)
	y.Gt(Duration{
		Years:   4,
		Months:  1,
		Days:    1,
		Hours:   13,
		Minutes: 8,
		Seconds: 31,
	})
	y.Le(x)
	y.Lt(y)
	y.Lt(Duration{
		Years:   4,
		Months:  1,
		Days:    1,
		Hours:   13,
		Minutes: 8,
		Seconds: 31,
	})

	var utc UTCTime
	utc.Tag()
	utc.IsPrimitive()
	utc.Layout()
	utc.Eq(UTCTime(noww))
	utc.Ne(UTCTime(noww))
	utc.Ge(UTCTime(noww))
	utc.Gt(UTCTime(noww))
	utc.Le(UTCTime(noww))
	utc.Lt(UTCTime(noww))

	var gt GeneralizedTime
	gt.Tag()
	gt.IsPrimitive()
	gt.Layout()
	NewUTCTime(`9908041543`)
	NewUTCTime(`990804154300`)
	NewUTCTime(`990804154300-0700`)
	parseCoreGTDateTime(`1`)
	parseGTTimezone(`blarg`, 444)
	parseGTTimezone("20250101123000Z1", 14)
	parseGTTimezone("20250101123000+00", 14)
	parseGTTimezone("20250101123000+0X30", 14)
	parseGTTimezone("20250101123000+2460", 14)
	parseGTTimezone("20250101123000X0000", 14)
	parseGeneralizedTime("20250101123000+2X30")
	parseGeneralizedTime("20250101123000ZEXTRA")
	parseGeneralizedTime("20250101123000.123456ZEXTRA")
	gt.Eq(GeneralizedTime(noww))
	gt.Ne(GeneralizedTime(noww))
	gt.Ge(GeneralizedTime(noww))
	gt.Gt(GeneralizedTime(noww))
	gt.Le(GeneralizedTime(noww))
	gt.Lt(GeneralizedTime(noww))

	tc := new(temporalCodec[GeneralizedTime])
	tc.write(&testPacket{}, nil)
	tc.read(&testPacket{}, TLV{}, nil)
	tc.Tag()
	tc.IsPrimitive()
	_ = tc.String()

	if f, ok := master[refTypeOf(GeneralizedTime(time.Time{}))]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(gt).(box)
	}

	dc := new(durationCodec[Duration])
	dc.write(&testPacket{}, nil)
	dc.read(&testPacket{}, TLV{}, nil)
	dc.Tag()
	dc.IsPrimitive()
	_ = dc.String()

	if f, ok := master[refTypeOf(Duration{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(dur).(box)
	}
}

type customGT GeneralizedTime

func (_ customGT) Tag() int           { return TagGeneralizedTime }
func (_ customGT) String() string     { return `` }
func (_ customGT) IsPrimitive() bool  { return true }
func (r customGT) Cast() time.Time    { return time.Time(r) }
func (_ customGT) Eq(_ Temporal) bool { return false }
func (_ customGT) Ne(_ Temporal) bool { return false }
func (_ customGT) Ge(_ Temporal) bool { return false }
func (_ customGT) Gt(_ Temporal) bool { return false }
func (_ customGT) Le(_ Temporal) bool { return false }
func (_ customGT) Lt(_ Temporal) bool { return false }

func TestCustomTemporal_withControls(t *testing.T) {
	RegisterTemporalAlias[customGT](TagGeneralizedTime,
		func([]byte) error {
			return nil
		},
		func(customGT) ([]byte, error) {
			return []byte{0x1, 0x1, 0xFF}, nil
		},
		func([]byte) (customGT, error) {
			return customGT(time.Now()), nil
		},
		nil)

	var cust customGT = customGT(time.Now())

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customGT
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

type customD Duration

func (_ customD) Tag() int          { return TagDuration }
func (_ customD) String() string    { return `` }
func (_ customD) IsPrimitive() bool { return true }

func TestCustomDuration_withControls(t *testing.T) {
	RegisterDurationAlias[customD](TagDuration,
		func([]byte) error {
			return nil
		},
		func(customD) ([]byte, error) {
			return []byte{0x1, 0x1, 0xFF}, nil
		},
		func([]byte) (customD, error) {
			return customD{}, nil
		},
		nil)

	var cust customD

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customD
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func Test_fillTemporalHooks_PanicsOnUnknownType(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	// Define a dummy type not covered by the switch
	var enc EncodeOverride[customGT]
	var dec DecodeOverride[customGT]

	// This should panic
	fillTemporalHooks(enc, dec)
}
