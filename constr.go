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

func (r ConstraintGroup[T]) phase(actual, expect int) (funk func(T) error) {
	funk = func(_ T) error { return nil }
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
func (r ConstraintGroup[T]) Validate(x T) error { return r.Constrain(x) }

/*
LiftConstraint adapts (or "converts") a [Constraint] for type U to type T.
*/
func LiftConstraint[T any, U any](convert func(T) U, c Constraint[U]) Constraint[T] {
	return func(x T) error { return c(convert(x)) }
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

func collectConstraint[T any](names []string) (ConstraintGroup[T], error) {
    var out ConstraintGroup[T]
    want := refTypeOf((*T)(nil)).Elem()

    for _, n := range names {
        n = trimL(lc(n), `^$`) // not part of the actual name, so toss them.
        entry, ok := constraintReg[n]
        if !ok {
            return nil, mkerrf("unknown constraint ", n)
        }

        if entry.typ != want && !want.ConvertibleTo(entry.typ) {
            return nil, mkerrf("constraint ", n, " not applicable to ", want.String())
        }

        fnVal := refValueOf(entry.fn)

        wrapper := func(u T) error {
            v := refValueOf(u)
            if v.Type() != entry.typ {
                v = v.Convert(entry.typ)
            }

            res := fnVal.Call([]reflect.Value{v})[0]
            if err := res.Interface(); err != nil {
                return err.(error)
            }
            return nil
        }

        out = append(out, wrapper)
    }

    return out, nil
}

func applyFieldConstraints(val any, names []string, expect rune) error {
	want := refTypeOf(val)

	for _, nm := range names {
		if nm = constrDoD(expect, lc(nm)); nm == "" {
			// Do not run constraint now.
			continue
		}
		ent, ok := constraintReg[nm]
		if !ok {
			return mkerrf("unknown constraint ", nm)
		}
		if ent.typ != want {
			return mkerrf("constraint ", nm, " not for ", want.String())
		}

		// Pass nm into getCachedEntry so the key can be built
		ce, err := getCachedFieldConstraint(ent, nm)
		if err != nil {
			return err
		}

		// Call either the raw func -OR- the .Constraint(...) method
		arg := refValueOf(val)
		var res reflect.Value
		if ce.isFunc {
			res = ce.fnVal.Call([]reflect.Value{arg})[0]
		} else {
			res = ce.methodVal.Call([]reflect.Value{arg})[0]
		}

		if err, _ := res.Interface().(error); err != nil {
			return err
		}
	}

	return nil
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

/*
cachedFieldConstraint holds the prepped reflection
values for one constraint + type to avoid repeated
(and unnecessary) reflection ops.
*/
type cachedFieldConstraint struct {
	fnVal     reflect.Value // always refValueOf(ent.fn)
	isFunc    bool          // true if fnVal.Kind() == Func
	methodVal reflect.Value // !isFunc == fnVal.MethodByName("Constraint")
}

/*
cachedFieldConstraints maps "type#constraintName" to its
cachedFieldConstraint, and is used in any sequence field
bearing a "constraint:name" struct tag.
*/
var cachedFieldConstraints = make(map[string]*cachedFieldConstraint)

// getCachedFieldConstraint returns or builds the cachedFieldConstraint for one constraint.
func getCachedFieldConstraint(ent constraintEntry, name string) (*cachedFieldConstraint, error) {
	keyFor := func(t reflect.Type, n string) string {
		return t.String() + "#" + lc(n)
	}

	key := keyFor(ent.typ, name)
	if ce, ok := cachedFieldConstraints[key]; ok {
		return ce, nil
	}

	fnVal := refValueOf(ent.fn)
	ce := &cachedFieldConstraint{fnVal: fnVal, isFunc: fnVal.Kind() == reflect.Func}

	if !ce.isFunc {
		if ce.methodVal = fnVal.MethodByName("Constraint"); !ce.methodVal.IsValid() {
			return nil, mkerrf("no Constraint method on ", refTypeOf(ent.fn).String())
		}
	}

	cachedFieldConstraints[key] = ce
	return ce, nil
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

/*
func expectCPhase(actual, expect int) bool {
	return actual == expect || actual == CodecConstraintBoth
}
*/

func init() {
	cachedFieldConstraints = make(map[string]*cachedFieldConstraint)
}
