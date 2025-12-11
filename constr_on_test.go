//go:build !asn1_no_constr_pf

package asn1plus

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ExampleNewEnumerated_withConstraint() {
	// Create a new Constraint using the hard-coded map
	// instance via the Enumeration "factory" function.
	//
	// Note that the map key can be any of the candidates
	// in the Numerical interface (e.g.: int32, uint8).
	// value should always be string.
	constraint := Enumeration(map[int]string{
		1: "one",
		2: "two",
		3: "three",
		4: "four",
		5: "five",
	})

	// Pass the constraint closure to NewEnumerated after
	// the input value 6.
	if _, err := NewEnumerated(6, constraint); err != nil {
		fmt.Println(err)
	}
	// Output: CONSTRAINT VIOLATION: ENUMERATED: disallowed ENUM value 6
}

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
func ExampleSize_uniqueSetOf() {
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
	sizeConstraint := Size[exampleSetOf](lower, upper)

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
func ExampleSize_sequenceOf() {
	// Define lower and upper bounds for the size constraint.
	lower, _ := NewInteger(1)
	upper, _ := NewInteger(3)

	// Create a SizeConstraint for types that implement Lengthy.
	constraint := Size[exampleSeqOf](lower, upper)

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

func ExampleSize_octetString() {
	// We require that the OctetString's logical length is between 3 and 6.
	lower, _ := NewInteger(3)
	upper, _ := NewInteger(6)
	constraint := Size[OctetString](lower, upper)

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
	Allowed := func(choices ...string) Constraint {
		allowedSet := make(map[string]struct{}, len(choices))
		for _, choice := range choices {
			// In this case, we want to support
			// caseIgnoreMatch behavior, so we
			// will lowercase normalize the value.
			allowedSet[strings.ToLower(choice)] = struct{}{}
		}
		return func(x any) (err error) {
			s, _ := x.(string)
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
	equipmentConstraint := Union(heavyMachinery, simpleTools)

	tool := `hammer`
	fmt.Printf("A %s is allowed: %t", tool, equipmentConstraint(tool) == nil)
	// Output: A hammer is allowed: true
}

func ExampleIntersection() {
	AllowedInts := func(values ...any) Constraint {
		allowed := make(map[string]struct{}, len(values))
		for _, v := range values {
			I, _ := v.(int)
			allowed[strconv.Itoa(I)] = struct{}{}
		}
		return func(i any) (err error) {
			var I Integer
			if I, err = NewInteger(i); err == nil {
				if _, ok := allowed[fmt.Sprint(I)]; !ok {
					err = fmt.Errorf("integer %v is not allowed; expected one of %v",
						I, values)
				}
			}
			return
		}
	}

	// CityClassSize allows only 15, 20, or 25 students.
	cityClassSizeConstraint := AllowedInts(15, 20, 25)

	// SuburbanClassSize allows only 20, 25, 30, or 35 students.
	suburbanClassSizeConstraint := AllowedInts(20, 25, 30, 35)

	// CombinedClassSize (analogous to our speedLimitConstraint)
	// accepts a class size if it satisfies either the CityClassSize
	// constraint or the SuburbanClassSize constraint, or it is an
	// exceptional case such as 10 or 40.
	combinedClassSizeConstraint := Union(
		cityClassSizeConstraint,
		suburbanClassSizeConstraint,
		AllowedInts(10),
		AllowedInts(40),
	)

	// CommonClassSize (analogous to RuralSpeedLimitConstraint) should
	// allow only the class sizes that are common to both districts,
	// i.e. sizes that are allowed for both city and suburban schools.
	commonClassSizeConstraint := Intersection(cityClassSizeConstraint, suburbanClassSizeConstraint)

	if !(combinedClassSizeConstraint(11) == nil || commonClassSizeConstraint(11) == nil) {
		fmt.Printf("No school for you, kid.")
	}
	// Output: No school for you, kid.
}

// ExampleTimePointRange demonstrates the use of [TimePointRangeConstraint].
func ExampleTimePointRange() {
	// Define a range from the beginning to the end of 2020.
	min, _ := NewDateTime("2020-01-01T00:00:00")
	max, _ := NewDateTime("2020-12-31T23:59:59")

	inside, _ := NewDateTime("2020-06-15T12:00:00")
	below, _ := NewDateTime("2019-12-31T23:59:59")
	above, _ := NewDateTime("2021-01-01T00:00:00")

	// Create the range constraint.
	rangeCon := TimePointRange(min, max)

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

func ExampleRecurrence() {
	// For our demonstration we set a period of 24 hours.
	period := 24 * time.Hour
	// Allowed window is from 0 to 1 hour.
	windowStart := 0 * time.Hour
	windowEnd := 1 * time.Hour

	// Parse two DateTime values. These types must implement Temporal.
	allowed, _ := NewDateTime("2020-11-22T00:30:00")
	notAllowed, _ := NewDateTime("2020-11-22T02:00:00")

	// Create the recurrence constraint.
	recCon := Recurrence[DateTime](period, windowStart, windowEnd)

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

func ExampleRange() {
	// Create a range constraint for int values from 10 to 20.
	rCon := Range[int](10, 20)

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

/*
ExampleConstraintGroup demonstrates constructing and using a group of constraints.
*/
func ExampleConstraintGroup_octetString() {
	noBadConstraint := func(val any) error {
		str, _ := val.(OctetString)
		if strings.Contains(str.String(), "bad") {
			return fmt.Errorf("value contains forbidden substring")
		}
		return nil
	}

	mustContainSpace := func(val any) error {
		str, _ := val.(OctetString)
		if !strings.ContainsRune(str.String(), ' ') {
			return fmt.Errorf("value must contain ' '")
		}
		return nil
	}

	// Combine three constraints into a ConstraintGroup.
	group := ConstraintGroup{
		SizeConstraint[Lengthy](5, 20),
		noBadConstraint,
		mustContainSpace,
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

func TestConstraint_codecov(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), errorNoPanic)
		}
	}()

	cgrp := ConstraintGroup{}
	cgrp.Validate(nil)

	RegisterTaggedConstraintGroup("duplicateConstraints", cgrp)
	RegisterTaggedConstraintGroup("duplicateConstraints", cgrp)
}

func TestFrom(t *testing.T) {
	from := From("abcxyz")
	if err := from(struct{}{}); err == nil {
		t.Error("expected error for struct{}")
	}
	if err := from([]byte("abc")); err != nil {
		t.Errorf("[]byte branch failed: %v", err)
	}
	if err := from(PrintableString("abc")); err != nil {
		t.Errorf("Primitive branch failed: %v", err)
	}
}

func TestConstraint_PanicOnDuplicateGroup(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), errorNoPanic)
		}
	}()
	cgrp := ConstraintGroup{}
	RegisterTaggedConstraintGroup("dup", cgrp)
	RegisterTaggedConstraintGroup("dup", cgrp) // trigger panic
}

func ExampleOctetString_sequenceFieldConstraintViolation() {
	uCOnly := func(x any) (err error) {
		o, _ := x.(OctetString)
		for i := 0; i < len(o); i++ {
			if !('A' <= rune(o[i]) && rune(o[i]) <= 'Z') {
				err = fmt.Errorf("Constraint violation: policy requires [A..Z] ASCII only")
				break
			}
		}
		return
	}

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
	oddDigitConstraint := func(x any) (err error) {
		o, _ := x.(OctetString)
		for i := 0; i < len(o); i++ {
			if '0' <= rune(o[i]) && rune(o[i]) <= '9' && rune(o[i])%2 != 0 {
				err = fmt.Errorf("Constraint violation: policy prohibits odd digits")
				break
			}
		}
		return
	}

	caseConstraint := func(x any) (err error) {
		o, _ := x.(OctetString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	RegisterTaggedConstraintGroup("groupedConstraint", ConstraintGroup{
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
