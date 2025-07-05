//go:build !asn1_no_constr_pf

package asn1plus

import (
	"time"

	"golang.org/x/exp/constraints"
)

/*
Union returns an instance of [Constraint] which checks if at least one (1)
of the provided constraints is satisfied. Essentially, this is an "OR"ed
operation.
*/
func Union[T any](constraints ...Constraint[T]) Constraint[T] {
	return func(x T) (err error) {
		var passed bool
		for i := 0; i < len(constraints) && !passed; i++ {
			passed = constraints[i](x) == nil
		}

		if !passed {
			err = mkerrf("union failed all ", itoa(len(constraints)), " constraints")
		}
		return
	}
}

/*
Intersection returns an instance of [Constraint] which checks if all of the
specified constraints are satisfied. Essentially, this is an "AND"ed operation.
*/
func Intersection[T any](constraints ...Constraint[T]) Constraint[T] {
	return func(x T) (err error) {
		for i := 0; i < len(constraints) && err == nil; i++ {
			err = constraints[i](x)
		}
		return
	}
}

/*
From returns an instance of [Constraint] that checks if a string value contains
illegal bytes (characters).
*/
func From(allowed string) Constraint[string] {
	allowedSet := make(map[rune]struct{})
	for _, r := range allowed {
		allowedSet[r] = struct{}{}
	}
	return func(s string) (err error) {
		for i := 0; i < len(s) && err == nil; i++ {
			if _, ok := allowedSet[rune(s[i])]; !ok {
				err = mkerrf("character ", string(s[i]), " at position ",
					itoa(i), " is not allowed")
			}
		}
		return
	}
}

/*
Equality returns an instance of [EqualityConstraint] that checks if two
comparable values are equal.

The variadic caseExactMatch input value declares whether case folding is
considered significant in the matching process of two strings. By default,
case folding is not significant.
*/
func Equality[T comparable](caseExactMatch ...bool) EqualityConstraint[T] {
	return func(assertion, actual T) (err error) {
		var eq bool

		// Special-case for string type:
		if sAssertion, ok := any(assertion).(string); ok {
			sActual, _ := any(actual).(string)
			if len(caseExactMatch) > 0 && caseExactMatch[0] {
				eq = sAssertion == sActual
			} else {
				eq = streqf(sAssertion, sActual)
			}
		} else {
			// For non-string types, use the built-in equality operator.
			eq = assertion == actual
		}

		if !eq {
			err = mkerr("values are not equal")
		}
		return
	}
}

/*
Ancestor returns an instance of [AncestralConstraint] that checks if two
slice types are ancestrally linked.
*/
func Ancestor[T any]() AncestralConstraint[T] {
	isEqual := func(a, b any) (eq bool) {
		if sa, ok := any(a).(interface{ String() string }); ok {
			if sb, ok := any(b).(interface{ String() string }); ok {
				eq = sa.String() == sb.String()
			}
			return
		}
		// Fallback: if T does not implement String, rely on direct equality.
		return a == b
	}

	return func(ancestor, descendant []T) (ok bool) {
		// If the candidate ancestor is longer than the descendant,
		// it cannot be a prefix.
		if len(ancestor) > len(descendant) {
			return false
		}
		for i := 0; i < len(ancestor); i++ {
			if !isEqual(ancestor[i], descendant[i]) {
				return false
			}
		}
		return true
	}
}

// DurationComponentConstraint returns a Constraint that applies a user-supplied check on a Duration.
// For instance, one could require that the seconds component always equals 30.
func DurationComponentConstraint(check func(Duration) error) Constraint[Duration] {
	return func(val Duration) error {
		return check(val)
	}
}

/*
RangeConstraint returns an instance of [Constraint] that checks if a value
of any ordered type is between the specified minimum and maximum.
*/
func RangeConstraint[T constraints.Ordered](min, max T) Constraint[T] {
	return func(val T) (err error) {
		if val < min || val > max {
			err = mkerr("value is out of range")
		}
		return
	}
}

/*
Size returns an instance of [Constraint] that checks if a value's logical
length does not exceed a particular magnitude.
*/
func SizeConstraint[T Lengthy](min, max Integer) Constraint[T] {
	return func(val T) (err error) {
		var size Integer
		if size, err = NewInteger(val.Len()); err == nil {
			if size.Lt(min) || size.Gt(max) {
				err = mkerrf("size ", size.String(), " is out of bounds [",
					min.String(), ", "+max.String(), "]")
			}
		}
		return
	}
}

// DurationRangeConstraint returns a Constraint for Duration values to ensure that the given value
// is not less than min and not greater than max.
func DurationRangeConstraint(min, max Duration) Constraint[Duration] {
	return func(val Duration) error {
		// If val is less than min or greater than max, reject.
		if val.Lt(min) || max.Lt(val) {
			return mkerrf("duration ", val.String(), " is not in the allowed range [",
				min.String(), ", ", max.String(), "]")
		}
		return nil
	}
}

// PropertyConstraint returns a Constraint that applies a user-defined check function.
// That function should return nil if the property is satisfied or an error otherwise.
func PropertyConstraint[T any](check func(T) error) Constraint[T] {
	return func(val T) error {
		return check(val)
	}
}

// RecurrenceConstraint returns a Constraint for temporal values that must fall within a recurring window.
// period is the recurrence period (e.g., 24h); windowStart and windowEnd represent the allowable offset
// (as durations) within each period.
func RecurrenceConstraint[T Temporal](period time.Duration, windowStart, windowEnd time.Duration) Constraint[T] {
	return func(val T) error {
		t := val.Cast()
		// For demonstration, using UnixNano remainder modulo the period.
		remainder := time.Duration(t.UnixNano()) % period
		if remainder < windowStart || remainder > windowEnd {
			return mkerrf("time ", val.String(), " (remainder ", remainder.String(),
				") is not within the recurrence window [", windowStart.String(), ", ",
				windowEnd.String(), "]")
		}
		return nil
	}
}

func TimeEqualConstraint[T Temporal](ref T) Constraint[T] {
	return func(val T) error {
		// Compare underlying time.Time representations.
		if !val.Cast().Equal(ref.Cast()) {
			return mkerrf("time ", val.String(), " is not equal to ", ref.String())
		}
		return nil
	}
}

func TimePointRangeConstraint[T Temporal](min, max T) Constraint[T] {
	return func(val T) error {
		t := val.Cast()
		if t.Before(min.Cast()) || t.After(max.Cast()) {
			return mkerrf("time ", val.String(), " is not in allowed range [",
				min.String(), ", ", max.String(), "]")
		}
		return nil
	}
}
