//go:build !asn1_no_dprc

package asn1plus

import (
	"fmt"
	"testing"
	"time"
)

func TestMustNewUTCTime_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()
	_ = MustNewUTCTime(struct{}{})
}

func ExampleUTCTime_withConstraint() {
	deadlineConstraint := func(x any) (err error) {
		o, _ := x.(Temporal)
		deadline, _ := NewUTCTime(`6810310904Z`)
		if o.Cast().After(deadline.Cast()) {
			err = fmt.Errorf("Constraint violation: you're late!")
		}
		return
	}

	_, err := NewUTCTime(`9104051614Z`, deadlineConstraint)
	fmt.Println(err)
	// Output: Constraint violation: you're late!
}

func ExampleUTCTime_dER() {
	// Parse time string into UTCTime instance
	ut, err := NewUTCTime(`9805061703Z`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// DER encode the UTCTime instance
	var pkt PDU
	if pkt, err = Marshal(ut); err != nil {
		fmt.Println(err)
		return
	}

	// Decode the DER PDU into new UTCTime instance
	var ut2 UTCTime
	if err = Unmarshal(pkt, &ut2); err != nil {
		fmt.Println(err)
		return
	}

	// Compare string representation
	fmt.Printf("%T values match: %t (%s)", ut, ut.String() == ut2.String(), ut2)
	// Output: asn1plus.UTCTime values match: true (9805061703Z)
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

			var pkt PDU
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

func TestUTCTime_codecov(_ *testing.T) {
	var utc UTCTime
	utc.Tag()
	utc.IsPrimitive()
	utc.Layout()
	noww := tnow()
	utc.Eq(UTCTime(noww))
	utc.Ne(UTCTime(noww))
	utc.Ge(UTCTime(noww))
	utc.Gt(UTCTime(noww))
	utc.Le(UTCTime(noww))
	utc.Lt(UTCTime(noww))

	NewUTCTime(`9908041543`)
	NewUTCTime(`990804154300`)
	NewUTCTime(`990804154300-0700`)
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
