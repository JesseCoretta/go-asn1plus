package asn1plus

/*
class.go implements the ASN.1 CLASS "template" structure.
*/

import "reflect"

/*
ClassInstance wraps a [Class] alongside concrete, parsed
field values.
*/
type ClassInstance struct {
	// Class descriptor to which the instance conforms.
	Class

	// Values holds each field’s final, typed value,
	// keyed by field Label.
	Values map[string]any
}

/*
Field returns the value associated with label. Case folding is
significant in the matching process, however the field label
need not include the ampersand (&) prefix.
*/
func (r ClassInstance) Field(label string) (any, bool) {
	label = classFieldLabelPrependAmp(label)
	out, found := r.Values[label]
	return out, found
}

/*
ClassInstanceFieldParser returns an any alongside an error following an
attempt to transform a raw user value into a typed class field
value.
*/
type ClassInstanceFieldParser func(any) (any, error)

/*
ClassInstanceFieldHandler customizes how [Class.New] binds fields.
*/
type ClassInstanceFieldHandler func(cfg *classFieldInstanceConfig)

type classFieldInstanceConfig struct {
	parsers map[string]ClassInstanceFieldParser
}

func classFieldLabelPrependAmp(label string) string {
	if !hasPfx(label, `&`) {
		label = `&` + label
	}
	return label
}

/*
FieldHandler returns a registered parser for a specific &Label as
a [ClassInstanceFieldHandler].

If the input label is not found within the receiver instance, a
dummy [ClassInstanceFieldHandler] containing an error is returned.
Note that while case folding is significant in the matching process,
the field label need not include the ampersand (&) prefix.

Instances of this type are used as input to the [Class.New] method,
should the associated field require special handling and/or validity
checks.
*/
func (r Class) FieldHandler(label string, p ClassInstanceFieldParser) ClassInstanceFieldHandler {
	label = classFieldLabelPrependAmp(label)
	if _, found := r.Field(label); !found {
		// Bogus field; replace the input parser
		// with a dummy that contains an error.
		p = func(_ any) (any, error) {
			return nil, classErrorf("Unknown field ", label)
		}
	}

	return func(cfg *classFieldInstanceConfig) {
		cfg.parsers[label] = p
	}
}

/*
New builds and returns a new bonafide [ClassInstance] alongside an error
following an attempt to read the input values and the current state of
the receiver instance into the return instance.

The input arguments may include zero (0) or more [ClassInstanceFieldHandler]
instances for specialized field handling or validity checks.
*/
func (r Class) New(
	vals map[string]any,
	opts ...ClassInstanceFieldHandler,
) (*ClassInstance, error) {
	var err error

	// apply options
	cfg := &classFieldInstanceConfig{
		parsers: make(map[string]ClassInstanceFieldParser)}

	for _, o := range opts {
		o(cfg)
	}

	inst := &ClassInstance{
		Class:  r,
		Values: make(map[string]any, len(r.Fields)),
	}

	for _, fld := range r.Fields {
		raw, ok := vals[fld.Label]
		if !ok {
			if !fld.Opt {
				err = classErrorf("missing mandatory field ", fld.Label)
				break
			}
			continue
		}

		// if importer provided a parser, use it
		if parser, found := cfg.parsers[fld.Label]; found {
			var val any
			if val, err = parser(raw); err != nil {
				err = classErrorf(fld.Label, " field parser error: ", err)
				break
			}
			inst.Values[fld.Label] = val
			continue
		}

		// default: simple type‐check
		if rt := refTypeOf(raw); rt != fld.Type {
			err = classErrorf("field ", fld.Label, ": expected ",
				fld.Type, " type, got ", rt)
			break
		}
		inst.Values[fld.Label] = raw
	}

	return inst, err
}

/*
ClassFieldKind defines the type of [ClassField] with which it
is associated.
*/
type ClassFieldKind uint8

const (
	ClassTypeField ClassFieldKind = iota
	ClassValueField
	ClassObjectField
)

/*
ClassField defines a single field ("row") in a [Class] template instance.
*/
type ClassField struct {
	Label string
	Kind  ClassFieldKind
	Type  reflect.Type
	Opt   bool // OPTIONAL / DEFAULT
}

/*
Class implements the ASN.1 CLASS template construct. Please note that
these instances are NOT intended to be encoded like SEQUENCES or SETs,
rather instances of this type are merely used to create compile-time
metadata instances (e.g.: literal definitions for a directory schema
or other such similar use case).

See [NewClass] to create a new instance, and see [Class.New] for the
means to create any associated [ClassInstance] instances.
*/
type Class struct {
	Name   string
	Fields []ClassField
	Syntax string // for WITH SYNTAX

	fieldLUT map[string]*ClassField
}

/*
NewClass populates and returns an instance of [Class]
alongside an error following an attempt to read the input name and
[ClassField] slices.
*/
func NewClass(name string, fields ...ClassField) (Class, error) {
	if name == "" {
		return Class{}, classErrorf("class template name may not be empty")
	}

	seen := map[string]bool{}
	for i, f := range fields {
		if !hasPfx(f.Label, "&") {
			return Class{}, classErrorf("field ", i, " (", f.Label, ") must start with ‘&’")
		}
		if seen[f.Label] {
			return Class{}, classErrorf("duplicate field ", f.Label)
		}
		if f.Type == nil {
			return Class{}, classErrorf("field ", f.Label, ": missing reflect.Type")
		}
		seen[f.Label] = true
	}

	lut := make(map[string]*ClassField, len(fields))
	for i := range fields {
		lut[fields[i].Label] = &fields[i]
	}
	return Class{Name: name, Fields: fields, fieldLUT: lut}, nil
}

/*
WithSyntax allows the assignment of a SYNTAX value in fluent form.
*/
func (r Class) WithSyntax(s string) Class {
	r.Syntax = s
	return r
}

/*
Field returns an instance of *[ClassField] alongside a presence-indicative
Boolean value following an attempt to retrieve a particular field by name.
*/
func (r Class) Field(label string) (*ClassField, bool) {
	f, ok := r.fieldLUT[label]
	return f, ok
}

/*
NewField returns a new instance of [ClassField] based upon the receiver value.
*/
func (k ClassFieldKind) NewField(
	label string, // Name of field (must start with '&')
	prototype any, // value that represents the type (e.g. OID{} or (*T)(nil))
	opt bool, // OPTIONAL / DEFAULT flag
) (ClassField, error) {

	if label == "" {
		return ClassField{}, classErrorf("ClassField: empty label")
	}
	if !hasPfx(label, "&") {
		return ClassField{}, classErrorf("ClassField ", label, ": must start with ‘&’")
	}
	if prototype == nil {
		return ClassField{}, classErrorf("ClassField ", label, ": nil prototype")
	}

	rt := refTypeOf(prototype)
	return ClassField{
		Label: label,
		Kind:  k,
		Type:  rt,
		Opt:   opt,
	}, nil
}
