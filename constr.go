package asn1plus

/*
constr.go contains constraint and constraint group components which
serve to implement ASN.1's constraints design for various types.
*/

import (
	"reflect"
	"time"

	"golang.org/x/exp/constraints"
)

/*
Lengthy is qualified through any type which bears the "Len() int" method.
*/
type Lengthy interface {
	Len() int
}

/*
Constraint implements a generic closure function signature meant to enforce
the constraining of values.
*/
type Constraint[T any] func(T) error

/*
EqualityConstraint implements a generic closure function signature meant to
compare two comparable values.
*/
type EqualityConstraint[T comparable] func(assertion, actual T) error

/*
AncestralConstraint implements a generic closure function signature meant
to determine whether ancestor and descendent are ancestrally linked.
*/
type AncestralConstraint[T any] func(ancestor, descendant []T) bool

/*
ConstraintGroup implements a wrapper of slices of [Constraint]. Slice instances
are added (and, thus, evaluated) in the order in which they are provided.
*/
type ConstraintGroup[T any] []Constraint[T]

/*
Constrain returns an error following the execution of all [Constraint] instances
against x which reside within the receiver isntance.
*/
func (r ConstraintGroup[T]) Constrain(x T) (err error) {
	for i := 0; i < len(r) && err == nil; i++ {
		if r[i] != nil {
			err = r[i](x)
		}
	}

	return
}

/*
Deprecated: Validate returns an error following the execution of all [Constraint]
instances against x which reside within the receiver isntance.

Use [ConstraintGroup.Constrain] instead.
*/
func (r ConstraintGroup[T]) Validate(x T) error { return r.Constrain(x) }

/*
LiftConstraint adapts (or "converts") a [Constraint] for type U to type T.
*/
func LiftConstraint[T any, U any](convert func(T) U, c Constraint[U]) Constraint[T] {
	return func(x T) error {
		return c(convert(x))
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

// DurationRangeConstraint returns a Constraint for Duration values to ensure that the given value
// is not less than min and not greater than max.
func DurationRangeConstraint(min, max Duration) Constraint[Duration] {
	return func(val Duration) error {
		// If val is less than min or greater than max, reject.
		if val.LessThan(min) || max.LessThan(val) {
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

/*
Ancestor returns an instance of [AncestralConstraint] that checks if two
slice types are ancestrally linked.
*/
func Ancestor[T any]() AncestralConstraint[T] {
	isEqual := func(a, b any) bool {
		if sa, ok := any(a).(interface{ String() string }); ok {
			sb, ok := any(b).(interface{ String() string })
			if !ok {
				return false
			}
			return sa.String() == sb.String()
		}
		// Fallback: if T does not implement String, rely on direct equality.
		return a == b
	}

	return func(ancestor, descendant []T) bool {
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
constraintEntry implements a private constraint registration type. Instances
of this type are used wherever constraints are references via tagged parameters
(e.g.: struct tags or in populated Options instances).
*/
type constraintEntry struct {
	typ reflect.Type
	fn  any
}

var constraintReg = map[string]constraintEntry{}

/*
RegisterTaggedConstraint assigns the provided [Constraint] function instance
to the package-level [Constraint] registry. The input name is used within
"asn1" struct tags and called via the "constraint" keyword when encountered,
e.g.:

	`asn1:"... other params ...,constraint:myConstraint"`

Multiple occurrences of "constraint:..." are permitted in tagged instructions.

It is not necessary to register [Constraint] instances if they are manually
(directly) passed to type constructors as input parameters.

This function will panic if a [Constraint] is registered under a name already
present within the registry. Case is not significant in the name registration
or matching processes.

See also [RegisterTaggedConstraintGroup].
*/
func RegisterTaggedConstraint[T any](name string, c Constraint[T]) {
	putConstraint(name, c)
}

/*
RegisterTaggedConstraintGroup assigns the provided [ConstraintGroup] instance
to the package-level [Constraint] registry. The input name is used within
"asn1" struct tags and called via the "constraint" keyword when executed, e.g.:

	`asn1:"... other params ...,constraint:myConstraintGroup"`

Multiple occurrences of "constraint:..." are permitted in tagged instructions.

It is not necessary to register [ConstraintGroup] instances if they are manually
(directly) passed to type constructors as variadic input parameters.

Use of this function over the [RegisterTaggedConstraint] function may be
preferable when many [Constraint] instances are in use and it is desirable
to keep tagged instructions as short as possible.

This function will panic if a [ConstraintGroup] is registered under a name
already present within the registry. Case is not significant in the name
registration or matching processes.
*/
func RegisterTaggedConstraintGroup[T any](name string, g ConstraintGroup[T]) {
	// wrap the group in a single Constraint[T] so callers don’t have to know.
	wrapped := Constraint[T](func(x T) error { return g.Validate(x) })
	putConstraint(name, wrapped)
}

func putConstraint[T any](name string, fn Constraint[T]) {
	key := lc(name)
	if _, dup := constraintReg[key]; dup {
		panic("asn1: duplicate constraint name " + name)
	}
	constraintReg[key] = constraintEntry{
		typ: reflect.TypeOf((*T)(nil)).Elem(),
		fn:  fn,
	}
}

func collectConstraint[T any](names []string) ([]Constraint[T], error) {
	var out []Constraint[T]
	want := reflect.TypeOf((*T)(nil)).Elem()

	for _, n := range names {
		e, ok := constraintReg[lc(n)]
		if !ok {
			return nil, mkerrf("unknown constraint ", n)
		}
		if e.typ != want {
			return nil, mkerrf("constraint ", n, " not applicable to ", want.String())
		}
		out = append(out, e.fn.(Constraint[T]))
	}
	return out, nil
}
