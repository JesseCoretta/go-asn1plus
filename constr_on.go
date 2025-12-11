//go:build !asn1_no_constr_pf

package asn1plus

import (
	"time"

	"golang.org/x/exp/constraints"
)

/*
Enumeration returns an instance of [Constraint] based upon a hard-coded
map. K may be any [Numerical] value, while V must always be a string.

If the input map is nil or zero, this function will panic.
*/
func Enumeration[K Numerical, V string](enum map[K]V) Constraint {
	if len(enum) == 0 {
		panic("ENUMERATED: constraint prefab error received nil or zero enum map")
	}

	keyType := refTypeOf((*K)(nil)).Elem()
	return func(x any) (err error) {
		v := refValueOf(x)
		if !v.Type().ConvertibleTo(keyType) {
			err = constraintViolationf("ENUMERATED: invalid type ", keyType,
				", expected Numerical qualifier")
			return
		}

		kVal := v.Convert(keyType).Interface().(K)
		if _, ok := enum[kVal]; !ok {
			err = constraintViolationf("ENUMERATED: disallowed ENUM value ", kVal)
		}
		return
	}
}

/*
Unsigned implements an [Integer] [Constraint] which prohibits negative numbers.
This closure instance is intended to be passed as a variadic argument to the
[NewInteger] and [MustNewInteger] functions.
*/
func Unsigned(x any) (err error) {
	if i, ok := x.(Integer); !ok {
		err = primitiveErrorf("Invalid Integer")
	} else if i.Lt(0) {
		err = errorNegativeInteger
	}
	return
}

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
Deprecated: RangeConstraint returns an instance of [Constraint] following
a call of [Range].

Use [Range] directly instead.
*/
func RangeConstraint[T constraints.Ordered](minimum, maximum T) Constraint {
	return Range[T](minimum, maximum)
}

/*
Range returns an instance of [Constraint] that checks if a value of any
[constraints.Ordered] type is between the specified minimum and maximum.
*/
func Range[T constraints.Ordered](minimum, maximum T) Constraint {
	return func(val any) error {
		v, ok := val.(T)
		if !ok {
			return constraintViolationf("type assertion to ordered failed")
		}
		if v < minimum || v > maximum {
			return constraintViolationf("value is out of range")
		}
		return nil
	}
}

/*
Deprecated: SizeConstraint returns an instance of [Constraint] following
a call of [Size].

Use [Size] directly instead.
*/
func SizeConstraint[T Lengthy](minimum, maximum any) Constraint {
	return Size[T](minimum, maximum)
}

/*
Size returns an instance of [Constraint] that is hard-coded with the input
minimum and maximum values for the purpose of checking if a value's logical
length is not outside of the specified boundaries.

This constructor is primarily intended to enforce upper bounds constraints
for certain ASN.1 primitive values, e.g.:

	ub-international-isdn-number INTEGER ::= 16
	InternationalISDNNumber ::= NumericString(SIZE (1..ub-international-isdn-number))
*/
func Size[T Lengthy](minimum, maximum any) Constraint {
	var (
		min, max Integer
		err      error
	)

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
		if err == nil {
			if size.Lt(min) || size.Gt(max) {
				err = constraintViolationf(
					"size ", size.String(),
					" is out of bounds [", min.String(),
					", "+max.String(), "]",
				)
			}
		}
		return err
	}
}

/*
Deprecated: RecurrenceConstraint returns a [Temporal] [Constraint] following
a call of [Recurrence].

Use [Recurrence] directly instead.
*/
func RecurrenceConstraint[T Temporal](period time.Duration, windowStart, windowEnd time.Duration) Constraint {
	return Recurrence[T](period, windowStart, windowEnd)
}

/*
Recurrence returns a [Temporal] [Constraint] for values that must fall
within a recurring window.

period is the recurrence period (e.g., 24h); windowStart and windowEnd
represent the allowable offset (as durations) within each period.
*/
func Recurrence[T Temporal](period time.Duration, windowStart, windowEnd time.Duration) Constraint {
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

/*
Deprecated: TimePointRangeConstraint returns a [Temporal] [Constraint]
following a call of [TimePointRange].

Use [TimePointRange] directly instead.
*/
func TimePointRangeConstraint[T Temporal](minimum, maximum T) Constraint {
	return TimePointRange[T](minimum, maximum)
}

/*
TimePointRange returns a [Temporal] [Constraint] function hard-coded with
the specified min and max values for the purpose of constraining [Temporal]
values to a specific time window.
*/
func TimePointRange[T Temporal](minimum, maximum T) Constraint {
	return func(val any) (err error) {
		tm, ok := val.(Temporal)
		if !ok {
			err = generalErrorf("Temporal assertion failed")
			return
		}
		t := tm.Cast()
		if t.Before(minimum.Cast()) || t.After(maximum.Cast()) {
			err = constraintViolationf("time ", tm.String(),
				" is not in allowed range [",
				minimum.String(), ", ", maximum.String(), "]")
		}
		return
	}
}
