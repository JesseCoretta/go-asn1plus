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
func Union(cs ...Constraint) Constraint {
	return func(x any) error {
		for _, c := range cs {
			if c(x) == nil {
				return nil
			}
		}
		return constraintViolationf("union failed all ",
			len(cs), " constraints")
	}
}

/*
Intersection returns an instance of [Constraint] which checks if all of the
specified constraints are satisfied. Essentially, this is an "AND"ed operation.
*/
func Intersection(cs ...Constraint) Constraint {
	return func(x any) (err error) {
		for i := 0; i < len(cs) && err == nil; i++ {
			err = cs[i](x)
		}
		return
	}
}

/*
From returns an instance of [Constraint] that checks if a string, []byte or [Primitive]
value contains illegal bytes (characters) as defined via the allowed input value.
*/
func From(allowed string) Constraint {
	allowedSet := make(map[rune]struct{})
	for _, r := range allowed {
		allowedSet[r] = struct{}{}
	}
	return func(x any) (err error) {
		var s string
		switch tv := x.(type) {
		case string:
			s = tv
		case []byte:
			s = string(tv)
		case Primitive:
			s = tv.String()
		default:
			err = generalErrorf("Assertion failed for string")
		}
		for i := 0; i < len(s) && err == nil; i++ {
			if _, ok := allowedSet[rune(s[i])]; !ok {
				err = constraintViolationf("character ", string(s[i]),
					" at position ", i, " is not allowed")
			}
		}
		return
	}
}

/*
RangeConstraint returns an instance of [Constraint] that checks if a value
of any ordered type is between the specified minimum and maximum.
*/
func RangeConstraint[T constraints.Ordered](min, max T) Constraint {
	return func(val any) error {
		v, ok := val.(T)
		if !ok {
			return constraintViolationf("type assertion to ordered failed")
		}
		if v < min || v > max {
			return constraintViolationf("value is out of range")
		}
		return nil
	}
}

/*
Size returns an instance of [Constraint] that checks if a value's logical
length is not outside of the boundaries defined by minimum and maximum.
*/
func SizeConstraint[T Lengthy](minimum, maximum any) Constraint {
	var min, max Integer
	var err error
	if min, err = assertInteger(minimum); err != nil {
		panic(err)
	}
	if max, err = assertInteger(maximum); err != nil {
		panic(err)
	}

	return func(val any) error {
		v, ok := val.(T)
		if !ok {
			return constraintViolationf("type assertion to Lengthy failed")
		}
		size, err := NewInteger(v.Len())
		if err != nil {
			return err
		}
		if size.Lt(min) || size.Gt(max) {
			return constraintViolationf(
				"size ", size.String(),
				" is out of bounds [", min.String(),
				", "+max.String(), "]",
			)
		}
		return nil
	}
}

/*
RecurrenceConstraint returns a Constraint for temporal values that
must fall within a recurring window. period is the recurrence period
(e.g., 24h); windowStart and windowEnd represent the allowable offset
(as durations) within each period.
*/
func RecurrenceConstraint[T Temporal](period time.Duration, windowStart, windowEnd time.Duration) Constraint {
	return func(val any) (err error) {
		tm, ok := val.(Temporal)
		if !ok {
			err = generalErrorf("Temporal assertion failed")
			return
		}
		remainder := time.Duration(tm.Cast().UnixNano()) % period
		if remainder < windowStart || remainder > windowEnd {
			err = constraintViolationf("time ", tm.String(),
				" (remainder ", remainder.String(),
				") is not within the recurrence window [",
				windowStart.String(), ", ",
				windowEnd.String(), "]")
		}
		return
	}
}

func TimePointRangeConstraint[T Temporal](min, max T) Constraint {
	return func(val any) (err error) {
		tm, ok := val.(Temporal)
		if !ok {
			err = generalErrorf("Temporal assertion failed")
			return
		}
		t := tm.Cast()
		if t.Before(min.Cast()) || t.After(max.Cast()) {
			err = constraintViolationf("time ", tm.String(),
				" is not in allowed range [",
				min.String(), ", ", max.String(), "]")
		}
		return
	}
}
