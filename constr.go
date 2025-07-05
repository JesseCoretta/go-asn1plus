package asn1plus

/*
constr.go contains constraint and constraint group components which
serve to implement ASN.1's constraints design for various types.
*/

import "reflect"

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
against x which reside within the receiver instance.
*/
func (r ConstraintGroup[T]) Constrain(x T) (err error) {
	debugEvent(EventEnter|EventConstraint, x)
	defer func() {
		debugEvent(EventExit|EventConstraint,
			newLItem(err))
	}()

	for i := 0; i < len(r) && err == nil; i++ {
		if r[i] != nil {
			err = r[i](x)
			debugEvent(EventConstraint|EventTrace,
				newLItem(i, "constraint"),
				newLItem(err))
		}
	}

	return
}

/*
Deprecated: Validate returns an error following the execution of all [Constraint]
instances against x which reside within the receiver instance.

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
	wrapped := Constraint[T](func(x T) error { return g.Constrain(x) })
	putConstraint(name, wrapped)
}

func putConstraint[T any](name string, fn Constraint[T]) {
	key := lc(name)

	debugEvent(EventEnter|EventConstraint,
		newLItem(key, "put constraint"))
	defer func() {
		debugEvent(EventExit | EventConstraint)
	}()

	if _, dup := constraintReg[key]; dup {
		panic("asn1: duplicate constraint name " + name)
	}
	constraintReg[key] = constraintEntry{
		typ: refTypeOf((*T)(nil)).Elem(),
		fn:  fn,
	}
}

func collectConstraint[T any](names []string) ([]Constraint[T], error) {
	var out []Constraint[T]
	want := refTypeOf((*T)(nil)).Elem()

	debugEvent(EventEnter|EventConstraint,
		newLItem(names, "get constraint(s)"))
	defer func() {
		debugEvent(EventExit | EventConstraint)
	}()

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

	debugEvent(EventConstraint|EventTrace,
		newLItem(len(out), "constraints found"))

	return out, nil
}
