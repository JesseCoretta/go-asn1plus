package asn1plus

import (
	"fmt"
	"testing"
	"time"
)

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
		WithEncoding(BER),
		WithOptions(opts),
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Packet hex: %s\n", pkt.Hex())

	var date string
	if err = Unmarshal(pkt, &date, WithOptions(opts)); err != nil {
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

	pkt, err := Marshal(`15:32:01`,
		WithEncoding(BER),
		WithOptions(opts),
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Packet hex: %s\n", pkt.Hex())

	var tod string
	if err = Unmarshal(pkt, &tod, WithOptions(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Time: %s\n", tod)

	// Output:
	// Packet hex: 1F20 08 31353A33323A3031
	// Time: 15:32:01
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

// constraint failure: > maxDur -------------------------------------------------

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
			if pkt, err = Marshal(gt, WithEncoding(rule)); err != nil {
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
			if pkt, err = Marshal(gt, WithEncoding(rule)); err != nil {
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
			if pkt, err = Marshal(gt, WithEncoding(rule)); err != nil {
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
			if pkt, err = Marshal(gt, WithEncoding(rule)); err != nil {
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
			if pkt, err = Marshal(gt, WithEncoding(rule)); err != nil {
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

func TestTime_codecov(_ *testing.T) {
	var pkt Packet

	var t Time
	t.Tag()
	t.Cast()
	t.IsPrimitive()

	var d Date
	d.Tag()
	d.Cast()
	d.IsPrimitive()
	d.Layout()
	d.read(pkt, TLV{}, Options{})
	d.read(invalidPacket{}, TLV{}, Options{})
	_, _ = parseDate(`1`)
	_, _ = parseDate(`2015?11=26`)
	_, _ = parseDate(`2015-13-36`)

	var dt DateTime
	dt.Tag()
	dt.Cast()
	dt.IsPrimitive()
	dt.Layout()
	dt.read(pkt, TLV{}, Options{})
	dt.read(invalidPacket{}, TLV{}, Options{})
	_, _ = parseDateTime(`1`)
	_, _ = parseDateTime(`2015?13-36T24:33:21`)
	_, _ = parseDateTime(`2015-13-36T14:33:21`)

	var tod TimeOfDay
	tod.Tag()
	tod.Cast()
	tod.IsPrimitive()
	tod.Layout()
	tod.read(invalidPacket{}, TLV{}, Options{})
	tod.read(pkt, TLV{}, Options{})
	_, _ = parseTimeOfDay(`1`)
	_, _ = parseTimeOfDay(`24?33=21`)
	_, _ = parseTimeOfDay(`24:53:21`)

	var dur Duration
	dur.Tag()
	dur.IsPrimitive()
	dur.read(invalidPacket{}, TLV{}, Options{})
	dur.read(pkt, TLV{}, Options{})
	NewDuration(`1`)
	NewDuration(`P1T1`)
	NewDuration(`P1YM3DT4H5M30S`)
	NewDuration(`PXYXMXDTXHXMXXS`)
	NewDuration(`PXYXMXDTXHXMXXS`)

	var utc UTCTime
	utc.Tag()
	utc.IsPrimitive()
	utc.Layout()
	utc.read(invalidPacket{}, TLV{}, Options{})
	utc.read(pkt, TLV{}, Options{})

	var gt GeneralizedTime
	gt.Tag()
	gt.IsPrimitive()
	gt.Layout()
	gt.read(invalidPacket{}, TLV{}, Options{})
	gt.read(pkt, TLV{}, Options{})
	NewUTCTime(`9908041543`)
	NewUTCTime(`990804154300`)
	NewUTCTime(`990804154300-0700`)
}
