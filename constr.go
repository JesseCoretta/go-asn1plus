package asn1plus

/*
constr.go contains constraint and constraint group components which
serve to implement ASN.1's constraints design for various types.
*/

import "reflect"

/*
Constraint implements a closure function signature meant to enforce
the constraining of a single value.

Instances of this type may be fed to various [Primitive] constructors,
and type registries throughout this package.
*/
type Constraint func(any) error

/*
ConstraintGroup implements a wrapper of slices of [Constraint]. Slice instances
are added (and, thus, evaluated) in the order in which they are provided.
*/
//type ConstraintGroup[T any] []Constraint[T]
type ConstraintGroup []Constraint

/*
Constrain returns an error following the execution of all [Constraint] instances
against x which reside within the receiver instance.
*/
func (r ConstraintGroup) Constrain(x any) (err error) {
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

func (r ConstraintGroup) phase(actual, expect int) (funk func(any) error) {
	funk = func(_ any) error { return nil }
	if actual == expect || actual == CodecConstraintBoth {
		funk = r.Constrain
	}
	return
}

/*
Deprecated: Validate returns an error following the execution of all [Constraint]
instances against x which reside within the receiver instance.

Use [ConstraintGroup.Constrain] instead.
*/
func (r ConstraintGroup) Validate(x any) error { return r.Constrain(x) }

/*
constraintEntry implements a private constraint registration type. Instances
of this type are used wherever constraints are references via tagged parameters
(e.g.: struct tags or in populated Options instances).
*/
type constraintEntry struct {
	typ reflect.Type
	fn  any
}

var constraintReg map[string]Constraint

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
func RegisterTaggedConstraint(name string, c Constraint) {
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
func RegisterTaggedConstraintGroup(name string, g ConstraintGroup) {
	wrapped := Constraint(func(x any) error { return g.Constrain(x) })
	putConstraint(name, wrapped)
}

func putConstraint(name string, fn Constraint) {
	key := lc(name)

	debugEvent(EventEnter|EventConstraint,
		newLItem(key, "put constraint"))
	defer func() {
		debugEvent(EventExit | EventConstraint)
	}()

	if _, dup := constraintReg[key]; dup {
		panic("asn1: duplicate constraint name " + name)
	} else if fn != nil {
		constraintReg[key] = fn
	}
}

func collectConstraint(names []string) (group ConstraintGroup, err error) {
	for _, n := range names {
		n = trimL(lc(n), `^$`)
		constraint, ok := constraintReg[n]
		if !ok {
			err = errorUnknownConstraint(n)
			break
		}
		group = append(group, constraint)
	}

	return
}

func applyFieldConstraints(val any, names []string, expect rune) (err error) {
	for _, nm := range names {
		if nm = constrDoD(expect, lc(nm)); nm != "" {
			fn, ok := constraintReg[nm]
			if !ok {
				return errorUnknownConstraint(nm)
			}
			if err = fn(val); err != nil {
				break
			}
		}
	}
	return
}

/*
constrDoD (Do-Or-Die) determines whether a constraint should be run
based on the presence (or lack) of certain instructions in the first
byte of the token.

	^ = encoding constraint only
	$ = decoding constraint only
	<neither> = both
*/
func constrDoD(expect rune, token string) (c string) {
	if token != "" {
		switch char := rune(token[0]); char {
		case '^', '$':
			if char == expect {
				c = token[1:]
			}
		default:
			c = token
		}
	}
	return
}

const (
	// CodecConstraintEncoding indicates that codec
	// operations should only execute constraints
	// during the encoding (write) phase.
	CodecConstraintEncoding = iota + 1

	// CodecConstraintDecoding indicates that codec
	// operations should only execute constraints
	// during the decoding (read) phase.
	CodecConstraintDecoding

	// CodecConstraintBoth indicates that codec
	// operations should execute constraints in
	// both the encoding (write) and decoding
	// (read) phases.
	CodecConstraintBoth
)

func init() {
	constraintReg = make(map[string]Constraint)
}
