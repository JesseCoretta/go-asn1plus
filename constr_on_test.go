//go:build !asn1_no_constr_pf

package asn1plus

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// sequence is an unexported type used only in examples.
// It implements the Lengthy interface.
type (
	exampleSeqOf []string
	exampleSetOf []string
)

func (s exampleSeqOf) Len() int {
	return len(s)
}

func (s exampleSetOf) Len() int {
	return len(s)
}

/*
This example demonstrates a size and uniqueness constraint of a SET OF.
Note that an imaginary type, exampleSetOf, is used for this example.
Thus, the reader would be expected to devise their own such type.

	type exampleSetOf []string

	// Qualify the Lengthy interface.
	func (r exampleSetOf) Len() int {
	    return len(r)
	}
*/
func ExampleSizeConstraint_uniqueSetOf() {
	UniqueConstraint := func(s exampleSetOf) error {
		seen := make(map[string]struct{}, len(s))
		for _, item := range s {
			if _, exists := seen[item]; exists {
				return fmt.Errorf("duplicate element: %s", item)
			}
			seen[item] = struct{}{}
		}
		return nil
	}

	// For this example, we require the set to have between 2 and 4 elements.
	lower, _ := NewInteger(2)
	upper, _ := NewInteger(4)
	sizeConstraint := SizeConstraint[exampleSetOf](lower, upper)

	// validSet has 3 unique elements.
	validSet := exampleSetOf{"apple", "banana", "cherry"}
	// invalidSet has 3 elements but fails uniqueness because "apple" appears twice.
	invalidSet := exampleSetOf{"apple", "banana", "apple"}

	// Apply the constraints sequentially.
	// For validSet:
	if err := sizeConstraint(validSet); err != nil {
		fmt.Println("validSet size error:", err)
	} else if err := UniqueConstraint(validSet); err != nil {
		fmt.Println("validSet uniqueness error:", err)
	} else {
		fmt.Println("validSet OK")
	}

	// For invalidSet:
	if err := sizeConstraint(invalidSet); err != nil {
		fmt.Println("invalidSet size error:", err)
	} else if err := UniqueConstraint(invalidSet); err != nil {
		fmt.Println("invalidSet uniqueness error:", err)
	} else {
		fmt.Println("invalidSet OK")
	}

	// Output:
	// validSet OK
	// invalidSet uniqueness error: duplicate element: apple
}

/*
This example demonstrates a size constraint of a SEQUENCE OF. Note that
an imaginary type, exampleSeqOf, is used for this example. Thus, the
reader would be expected to devise their own such type.

	type exampleSeqOf []string

	// Qualify the Lengthy interface.
	func (r exampleSeqOf) Len() int {
	    return len(r)
	}
*/
func ExampleSizeConstraint_sequenceOf() {
	// Define lower and upper bounds for the size constraint.
	lower, _ := NewInteger(1)
	upper, _ := NewInteger(3)

	// Create a SizeConstraint for types that implement Lengthy.
	constraint := SizeConstraint[exampleSeqOf](lower, upper)

	// Define two sequences using the unexported type "sequence".
	validSeq := exampleSeqOf{"a", "b"}             // length 2 -- PASS
	invalidSeq := exampleSeqOf{"a", "b", "c", "d"} // length 4 -- FAIL

	// Test the valid sequence.
	if err := constraint(validSeq); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("validSeq OK")
	}

	// Test the invalid sequence.
	if err := constraint(invalidSeq); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("invalidSeq OK")
	}

	// Output:
	// validSeq OK
	// CONSTRAINT VIOLATION: size 4 is out of bounds [1, 3]
}

func ExampleSizeConstraint_octetString() {
	// We require that the OctetString's logical length is between 3 and 6.
	lower, _ := NewInteger(3)
	upper, _ := NewInteger(6)
	constraint := SizeConstraint[OctetString](lower, upper)

	valid := OctetString("abcd")       // length 4 => valid
	invalid := OctetString("abcdefgh") // length 8 => invalid

	if err := constraint(valid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("valid OK")
	}

	if err := constraint(invalid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("invalid OK")
	}

	// Output:
	// valid OK
	// CONSTRAINT VIOLATION: size 8 is out of bounds [3, 6]
}

func ExampleUnion() {
	// This user-authored closure evaluates the input string choices
	// to determine whether at least one satisfies a constraint.
	Allowed := func(choices ...string) Constraint[string] {
		allowedSet := make(map[string]struct{}, len(choices))
		for _, choice := range choices {
			// In this case, we want to support
			// caseIgnoreMatch behavior, so we
			// will lowercase normalize the value.
			allowedSet[strings.ToLower(choice)] = struct{}{}
		}
		return func(s string) (err error) {
			if _, ok := allowedSet[strings.ToLower(s)]; !ok {
				err = fmt.Errorf("value %q is not allowed; expected one of %v", s, choices)
			}
			return
		}
	}

	// The user may then define certain categories containing
	// permitted values.
	heavyMachinery := Allowed("Lathe", "Hydraulic press")
	simpleTools := Allowed("Hammer", "Screwdriver")
	equipmentConstraint := Union[string](heavyMachinery, simpleTools)

	tool := `hammer`
	fmt.Printf("A %s is allowed: %t", tool, equipmentConstraint(tool) == nil)
	// Output: A hammer is allowed: true
}

func ExampleIntersection() {
	AllowedInts := func(values ...Integer) Constraint[Integer] {
		allowed := make(map[string]struct{}, len(values))
		for _, v := range values {
			allowed[fmt.Sprint(v)] = struct{}{}
		}
		return func(i Integer) (err error) {
			if _, ok := allowed[fmt.Sprint(i)]; !ok {
				err = fmt.Errorf("integer %v is not allowed; expected one of %v", i, values)
			}
			return
		}
	}

	fifteen, _ := NewInteger(15)
	twenty, _ := NewInteger(20)
	twentyFive, _ := NewInteger(25)
	thirty, _ := NewInteger(30)
	thirtyFive, _ := NewInteger(35)
	ten, _ := NewInteger(10)
	forty, _ := NewInteger(40)

	// CityClassSize allows only 15, 20, or 25 students.
	cityClassSizeConstraint := AllowedInts(fifteen, twenty, twentyFive)

	// SuburbanClassSize allows only 20, 25, 30, or 35 students.
	suburbanClassSizeConstraint := AllowedInts(twenty, twentyFive, thirty, thirtyFive)

	// CombinedClassSize (analogous to our speedLimitConstraint)
	// accepts a class size if it satisfies either the CityClassSize
	// constraint or the SuburbanClassSize constraint, or it is an
	// exceptional case such as 10 or 40.
	combinedClassSizeConstraint := Union[Integer](
		cityClassSizeConstraint,
		suburbanClassSizeConstraint,
		AllowedInts(ten),
		AllowedInts(forty),
	)

	// CommonClassSize (analogous to RuralSpeedLimitConstraint) should
	// allow only the class sizes that are common to both districts,
	// i.e. sizes that are allowed for both city and suburban schools.
	commonClassSizeConstraint := Intersection[Integer](cityClassSizeConstraint, suburbanClassSizeConstraint)

	eleven, _ := NewInteger(11)

	if !(combinedClassSizeConstraint(eleven) == nil || commonClassSizeConstraint(eleven) == nil) {
		fmt.Printf("No school for you, kid.")
	}
	// Output: No school for you, kid.
}

// ExampleTimeEqualConstraint demonstrates the use of TimeEqualConstraint.
func ExampleTimeEqualConstraint() {
	// Assume NewDateTime parses a value and that DateTime implements Temporal.
	ref, _ := NewDateTime("2020-11-22T18:30:23")
	same, _ := NewDateTime("2020-11-22T18:30:23")
	diff, _ := NewDateTime("2020-11-22T18:30:24")

	// Create an equality constraint against ref.
	eqCon := TimeEqualConstraint(ref)

	// Check an identical value.
	if err := eqCon(same); err != nil {
		fmt.Println("unexpected error:", err)
	} else {
		fmt.Println("equal constraint passes for identical value")
	}

	// Check a slightly different value.
	if err := eqCon(diff); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("error: constraint passed for different value")
	}

	// Output:
	// equal constraint passes for identical value
	// CONSTRAINT VIOLATION: time 2020-11-22T18:30:24 is not equal to 2020-11-22T18:30:23
}

// ExampleTimePointRangeConstraint demonstrates the use of [TimePointRangeConstraint].
func ExampleTimePointRangeConstraint() {
	// Define a range from the beginning to the end of 2020.
	min, _ := NewDateTime("2020-01-01T00:00:00")
	max, _ := NewDateTime("2020-12-31T23:59:59")

	inside, _ := NewDateTime("2020-06-15T12:00:00")
	below, _ := NewDateTime("2019-12-31T23:59:59")
	above, _ := NewDateTime("2021-01-01T00:00:00")

	// Create the range constraint.
	rangeCon := TimePointRangeConstraint(min, max)

	// Check a value inside the range.
	if err := rangeCon(inside); err != nil {
		fmt.Println("inside time failed:", err)
	} else {
		fmt.Println("inside time OK")
	}
	// Check a value below the range.
	if err := rangeCon(below); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("error: below time passed")
	}
	// Check a value above the range.
	if err := rangeCon(above); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("error: above time passed")
	}

	// Output:
	// inside time OK
	// CONSTRAINT VIOLATION: time 2019-12-31T23:59:59 is not in allowed range [2020-01-01T00:00:00, 2020-12-31T23:59:59]
	// CONSTRAINT VIOLATION: time 2021-01-01T00:00:00 is not in allowed range [2020-01-01T00:00:00, 2020-12-31T23:59:59]
}

// ExampleDurationRangeConstraint demonstrates the use of [DurationRangeConstraint].
func ExampleDurationRangeConstraint() {
	// Define minimum and maximum durations.
	min, _ := NewDuration("P1Y2M3DT4H5M6S")
	max, _ := NewDuration("P2Y3M4DT5H6M7S")

	// A valid duration equal to the minimum.
	valid, _ := NewDuration("P1Y2M3DT4H5M6S")
	// A duration just below the minimum.
	lower, _ := NewDuration("P1Y2M3DT4H5M5S")
	// A duration just above the maximum.
	higher, _ := NewDuration("P2Y3M4DT5H6M8S")

	// Create the Duration range constraint.
	durCon := DurationRangeConstraint(min, max)

	// Check the valid duration.
	if err := durCon(valid); err != nil {
		fmt.Println("valid duration failed:", err)
	} else {
		fmt.Println("valid duration OK")
	}
	// Check the duration below the minimum.
	if err := durCon(lower); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("error: lower duration passed")
	}
	// Check the duration above the maximum.
	if err := durCon(higher); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("error: higher duration passed")
	}

	// Output:
	// valid duration OK
	// CONSTRAINT VIOLATION: duration P1Y2M3DT4H5M5S is not in the allowed range [P1Y2M3DT4H5M6S, P2Y3M4DT5H6M7S]
	// CONSTRAINT VIOLATION: duration P2Y3M4DT5H6M8S is not in the allowed range [P1Y2M3DT4H5M6S, P2Y3M4DT5H6M7S]
}

func ExampleRecurrenceConstraint() {
	// For our demonstration we set a period of 24 hours.
	period := 24 * time.Hour
	// Allowed window is from 0 to 1 hour.
	windowStart := 0 * time.Hour
	windowEnd := 1 * time.Hour

	// Parse two DateTime values. These types must implement Temporal.
	allowed, _ := NewDateTime("2020-11-22T00:30:00")
	notAllowed, _ := NewDateTime("2020-11-22T02:00:00")

	// Create the recurrence constraint.
	recCon := RecurrenceConstraint[DateTime](period, windowStart, windowEnd)

	// Apply the constraint to the value that is within the allowed window.
	if err := recCon(allowed); err != nil {
		fmt.Println("allowed value fails:", err)
	} else {
		fmt.Println("allowed value passes")
	}

	// Apply the constraint to the value that is outside the allowed window.
	if err := recCon(notAllowed); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("notAllowed value passes")
	}

	// Output:
	// allowed value passes
	// CONSTRAINT VIOLATION: time 2020-11-22T02:00:00 (remainder 2h0m0s) is not within the recurrence window [0s, 1h0m0s]
}

func ExampleRangeConstraint() {
	// Create a range constraint for int values from 10 to 20.
	rCon := RangeConstraint[int](10, 20)

	// Check a value that is within the range.
	if err := rCon(15); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("15 passes")
	}

	// Check a value that is out of range.
	if err := rCon(25); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("25 passes")
	}

	// Output:
	// 15 passes
	// CONSTRAINT VIOLATION: value is out of range
}

func ExampleFrom() {
	// Define the allowed set of characters.
	allowed := "ABC123"
	// Get the string constraint.
	strCon := From(allowed)

	// A valid string containing only allowed characters.
	valid := "A1B2C3"
	// An invalid string that includes an illegal character.
	invalid := "A1B2C3X"

	if err := strCon(valid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("valid passes")
	}

	if err := strCon(invalid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("invalid passes")
	}

	// Output:
	// valid passes
	// CONSTRAINT VIOLATION: character X at position 6 is not allowed
}

func ExampleEqualityConstraint_caseIgnoreMatch() {
	if err := Equality[string]()("hello", "Hello"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Constraint passed")
	}
	// Output: Constraint passed
}

func ExampleEqualityConstraint_caseExactMatch() {
	if err := Equality[string](true)("hello", "Hello"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Constraint passed")
	}
	// Output: CONSTRAINT VIOLATION: values are not equal
}

func ExampleAncestor_stringSlices() {
	oid1 := []string{"1", "3", "6", "1", "4", "1"}
	oid2 := []string{"1", "3", "6", "1", "4", "1", "1"}
	oid3 := []string{"1", "3", "6", "1", "5", "1", "1"}

	ac := Ancestor[string]()

	fmt.Println("oid1 is ancestor of oid2?", ac(oid1, oid2))
	fmt.Println("oid1 is ancestor of oid3?", ac(oid1, oid3))
	// Output:
	// oid1 is ancestor of oid2? true
	// oid1 is ancestor of oid3? false
}

func ExampleAncestor_objectIdentifier() {
	oid1, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1)
	oid2, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)

	// Instead of treating the OIDs as actual OIDs,
	// we need to put them back into an explicit
	// slice form ([]Integer).
	ac := Ancestor[Integer]()
	fmt.Println("oid1 is ancestor of oid2?", ac([]Integer(oid1), []Integer(oid2)))
	// Output:
	// oid1 is ancestor of oid2? true
}

func ExampleLiftConstraint_sizeConstraint() {
	// Define bounds for the size: between 5 and 10.
	min, _ := NewInteger(5)
	max, _ := NewInteger(10)

	// Create a SizeConstraint for any Lengthy type.
	sizeConstraint := SizeConstraint[Lengthy](min, max)

	// Lift that constraint so it applies to OctetString.
	// The conversion simply treats an OctetString as a Lengthy (since it implements Len()).
	liftedConstraint := LiftConstraint(func(o OctetString) Lengthy { return o }, sizeConstraint)

	// Create two OctetStrings.
	valid := OctetString("123456") // length 6, valid.
	invalid := OctetString("1234") // length 4, invalid.

	// Validate the valid value.
	if err := liftedConstraint(valid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("valid: ok")
	}

	// Validate the invalid value.
	if err := liftedConstraint(invalid); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("invalid: ok")
	}

	// Output:
	// valid: ok
	// CONSTRAINT VIOLATION: size 4 is out of bounds [5, 10]
}

/*
noBadSubstring returns a constraint that fails if the input string contains
the substring "bad".

Used for examples only.
*/
func noBadSubstring[T OctetString]() Constraint[T] {
	return func(val T) error {
		if strings.Contains(string(val), "bad") {
			return fmt.Errorf("value contains forbidden substring")
		}
		return nil
	}
}

/*
mustContainChar returns a constraint that fails if the given character
is not present in the string value.

Used for examples only.
*/
func mustContainChar[T ~string](ch rune) Constraint[T] {
	return func(val T) error {
		if !strings.ContainsRune(string(val), ch) {
			return fmt.Errorf("value must contain '%c'", ch)
		}
		return nil
	}
}

/*
ExampleConstraintGroup demonstrates constructing and using a group of constraints
(including one "lifted" constraint) on an OctetString.

For the purposes of this example, assume the following example functions exists:

	// Fictional function to scan for a bad word.
	func noBadSubstring[T OctetString]() Constraint[T] {
	    return func(val T) error {
	        if strings.Contains(string(val), "bad") {
	            return errors.New("value contains forbidden substring")
	        }
	        return nil
	    }
	}

	// Fictional function to scan for a required space.
	func mustContainChar[T ~string](ch rune) Constraint[T] {
	    return func(val T) error {
	        if !strings.ContainsRune(string(val), ch) {
	            return fmt.Errorf("value must contain '%c'", ch)
	        }
	        return nil
	    }
	}
*/
func ExampleConstraintGroup_octetString() {
	five, _ := NewInteger(5)
	twenty, _ := NewInteger(20)

	// Create a SizeConstraint for any Lengthy value. We want the
	// OctetString to be at least 5 and at most 20 characters.
	sizeConstraint := LiftConstraint(func(o OctetString) Lengthy { return o }, SizeConstraint[Lengthy](five, twenty))

	// Also, we require that the string not contain the substring "bad".
	noBadConstraint := noBadSubstring[OctetString]()

	// The mustContainChar constraint is defined for any T ~string.
	// Here, we want to ensure that there is at least one space (' ')
	// in the value. Since mustContainChar[string] actually returns a
	// Constraint[string], we use LiftConstraint to convert it into a
	// Constraint[OctetString]. The conversion function converts an
	// OctetString to string.
	spaceConstraint := LiftConstraint(func(o OctetString) string { return string(o) }, mustContainChar[string](' '))

	// Combine the three constraints into a ConstraintGroup.
	group := ConstraintGroup[OctetString]{
		sizeConstraint,
		noBadConstraint,
		spaceConstraint,
	}

	// Define a set of named tests with values.
	tests := []struct {
		name string
		val  OctetString
	}{
		{"valid", OctetString("hello world")},
		{"tooShort", OctetString("hi")},
		{"withBad", OctetString("this is bad indeed")},
		{"missingChar", OctetString("helloworld")},
	}

	// Validate each test value.
	for _, tc := range tests {
		err := group.Constrain(tc.val)
		if err != nil {
			fmt.Printf("%s: %v\n", tc.name, err)
		} else {
			fmt.Printf("%s: ok\n", tc.name)
		}
	}

	// Output:
	// valid: ok
	// tooShort: CONSTRAINT VIOLATION: size 2 is out of bounds [5, 20]
	// withBad: value contains forbidden substring
	// missingChar: value must contain ' '
}

func ExampleLiftConstraint() {
	// Define any custom function
	allowedRange := func(i Integer) error {
		var value int64
		if !i.big {
			value = i.native
		} else {
			// For simplicity, only handle *big.Int values that fit in int64.
			if i.bigInt.IsInt64() {
				value = i.bigInt.Int64()
			} else {
				return fmt.Errorf("integer too large for range check")
			}
		}
		if value < 10 || value > 100 {
			return fmt.Errorf("value %d not in range [10, 100]", value)
		}
		return nil
	}

	constraint := LiftConstraint(func(i Integer) Integer { return i }, allowedRange)
	fmt.Printf("%T\n", constraint)
	// Output: asn1plus.Constraint[github.com/JesseCoretta/go-asn1plus.Integer]
}

func TestConstraint_codecov(t *testing.T) {
	slice1 := []string{"1", "3", "6", "1", "4", "1", "1"}
	slice2 := []string{"1", "3", "6", "1", "5", "1"}

	ac := Ancestor[string]()
	ac(slice1, slice2)

	equality := Equality[int]()
	equality(1, 2)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	cgrp := ConstraintGroup[OctetString]{}
	cgrp.Validate(nil)

	RegisterTaggedConstraintGroup("duplicateConstraints", cgrp)
	RegisterTaggedConstraintGroup("duplicateConstraints", cgrp)
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

func TestNewDuration_constraintViolation(t *testing.T) {
	tooBig := "P20Y" // 20 years, well above maxDur
	if _, err := NewDuration(tooBig, DurationRangeConstraint(Duration{}, Duration{Years: 9})); err == nil {
		t.Fatalf("expected range-constraint error for %q, got nil", tooBig)
	}
}

func ExampleOctetString_sequenceFieldConstraintViolation() {
	uCOnly := LiftConstraint(func(o OctetString) OctetString { return o },
		// Prohibit any lower-case ASCII letters
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if !('A' <= rune(o[i]) && rune(o[i]) <= 'Z') {
					err = fmt.Errorf("Constraint violation: policy requires [A..Z] ASCII only")
					break
				}
			}
			return
		})

	RegisterTaggedConstraint("ucOnly", uCOnly)

	type MySequence struct {
		Name  PrintableString
		Badge OctetString `asn1:"constraint:ucOnly"`
	}

	my := MySequence{
		PrintableString("Print me"),
		OctetString(`e45aXY`),
	}

	if _, err := Marshal(my); err != nil {
		fmt.Println(err)
	}
	// Output: Constraint violation: policy requires [A..Z] ASCII only
}

func ExampleOctetString_sequenceFieldConstraintGroupViolation() {
	oddDigitConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		// Prohibit use of any odd digit characters
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' && rune(o[i])%2 != 0 {
					err = fmt.Errorf("Constraint violation: policy prohibits odd digits")
					break
				}
			}
			return
		})

	caseConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		// Prohibit any lower-case ASCII letters
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	RegisterTaggedConstraintGroup("groupedConstraint", ConstraintGroup[OctetString]{
		oddDigitConstraint,
		caseConstraint,
	})

	type MySequence struct {
		Name PrintableString

		// Constraint Name Syntax
		// ^ means only run during ENCODING (at field read)
		// $ means only run during DECODING (at field write)
		// <neither> means run during both (inefficient)
		Badge OctetString `asn1:"constraint:^groupedConstraint"`
	}

	my := MySequence{
		PrintableString("Print me"),
		OctetString(`e45aXY`),
	}

	if _, err := Marshal(my); err != nil {
		fmt.Println(err)
	}
	// Output: Constraint violation: policy prohibits odd digits
}
