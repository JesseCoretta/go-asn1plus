package asn1plus

/*
class.go implements the ASN.1 CLASS "template" structure.
*/

import "reflect"

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
ClassField defines a single field ("row") in a [Class] instance.
*/
type ClassField struct {
	Label string
	Kind  ClassFieldKind
	Typ   reflect.Type
	Opt   bool // OPTIONAL / DEFAULT
}

/*
Class implements the ASN.1 CLASS "template" construct.  Note that such
instances are NOT intended to be encoded like SEQUENCES or SETs, rather
instances of this type are merely intended to store compile-time metadata
(e.g.: a schema).

See [NewClass] to create a new instance.
*/
type Class struct {
	Name   string
	Fields []ClassField
	Syntax string // for WITH SYNTAX

	fieldLUT map[string]*ClassField
}

/*
NewClass populates and returns an instance of [Class] alongside an
error following an attempt to read the input name and [ClassField]
slices.
*/
func NewClass(name string, fields ...ClassField) (Class, error) {
	if name == "" {
		return Class{}, mkerr("class name may not be empty")
	}

	seen := map[string]bool{}
	for i, f := range fields {
		if !hasPfx(f.Label, "&") {
			return Class{}, mkerrf("field ", itoa(i), " (", f.Label, ") must start with ‘&’")
		}
		if seen[f.Label] {
			return Class{}, mkerrf("duplicate field ", f.Label)
		}
		if f.Typ == nil {
			return Class{}, mkerrf("field ", f.Label, ": missing reflect.Type")
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
		return ClassField{}, mkerr("ClassField: empty label")
	}
	if !hasPfx(label, "&") {
		return ClassField{}, mkerrf("ClassField ", label, ": must start with ‘&’")
	}
	if prototype == nil {
		return ClassField{}, mkerrf("ClassField ", label, ": nil prototype")
	}

	rt := refTypeOf(prototype)
	return ClassField{
		Label: label,
		Kind:  k,
		Typ:   rt,
		Opt:   opt,
	}, nil
}
