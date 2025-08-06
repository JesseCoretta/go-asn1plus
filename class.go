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
significant in the matching process.
*/
func (r ClassInstance) Field(label string) (any, bool) {
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
Case folding is significant in the matching process. Note that the
label value may represent a base field name (e.g.: "&id") or an
alternative 'WITH SYNTAX' label (e.g.: "ID").

Instances of this type are used as input to the [Class.New] method,
should the associated field require special handling and/or validity
checks.
*/
func (r Class) FieldHandler(label string, p ClassInstanceFieldParser) ClassInstanceFieldHandler {
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

	cfg := &classFieldInstanceConfig{
		parsers: make(map[string]ClassInstanceFieldParser)}

	for _, o := range opts {
		o(cfg)
	}

	inst := &ClassInstance{
		Class:  r,
		Values: make(map[string]any, len(r.Fields)),
	}

	addV := func(fld *ClassField, value any) {
		inst.Values[fld.Label] = value
		if fld.Label != fld.WithLabel && fld.WithLabel != "" {
			inst.Values[fld.WithLabel] = value
		}
	}

	getP := func(fld *ClassField) (p ClassInstanceFieldParser, ok bool) {
		if p, ok = cfg.parsers[fld.Label]; !ok {
			p, ok = cfg.parsers[fld.WithLabel]
		}
		return
	}

	for _, fld := range r.Fields {
		var (
			label string
			raw   any
			ok    bool
		)

		ptrFld := r.fieldLUT[fld.Label]

		if raw, ok = vals[fld.Label]; !ok {
			if raw, ok = vals[fld.WithLabel]; !ok {
				if !fld.opts.Optional {
					err = classErrorf("missing mandatory field ", fld.Label)
					break
				}
				continue
			}
		}
		label = fld.deferLabel()

		// if importer provided a parser, use it
		if parser, found := getP(ptrFld); found {
			var val any
			if val, err = parser(raw); err != nil {
				err = classErrorf(label, " field parser error: ", err)
				break
			}

			addV(ptrFld, val)
			if err = r.checkUnique(ptrFld, val, inst); err != nil {
				break
			}
			continue
		}

		// Check if the registered type is a dynType instance,
		// which indicates the user passed nil as a prototype
		// during the original CLASS template creation. If so,
		// allow any type.
		if rt := refTypeOf(raw); rt != fld.Type && refDynType != fld.Type {
			err = classErrorf("field ", label, ": expected ",
				fld.Type, " type, got ", rt)
			break
		}

		addV(ptrFld, raw)
		if err = r.checkUnique(ptrFld, raw, inst); err != nil {
			break
		}
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
	Label, // base label
	WithLabel string // WITH SYNTAX label
	Kind ClassFieldKind
	Type reflect.Type
	opts *Options
}

/*
deferLabel returns the value associated with the "WithLabel" field (if non
zero), else the value associated with the "Label" field is returned as a
fallback.
*/
func (r ClassField) deferLabel() (label string) {
	label = r.Label
	if r.WithLabel != "" {
		label = r.WithLabel
	}
	return
}

func (r *Class) checkUnique(fld *ClassField, raw any, inst *ClassInstance) (err error) {
	// If enforced for this field, confirm value uniqueness.
	if fld.opts.Unique {
		if _, exists := r.uniqueLUT[fld.Label][raw]; exists {
			err = classErrorf("uniqueness violation for CLASS ",
				r.Name, ", field ", fld.Label)
		} else {
			r.uniqueLUT[fld.Label][raw] = inst
			if fld.Label != fld.WithLabel && fld.WithLabel != "" {
				r.uniqueLUT[fld.WithLabel][raw] = inst
			}
		}
	}
	return
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

	fieldLUT  map[string]*ClassField
	uniqueLUT map[string]map[any]*ClassInstance
}

/*
NewClass populates and returns an instance of [Class] alongside an
error following an attempt to read the input name and [ClassField]
slices. See the [ClassFieldKind.NewField] method for a means of
creating new instances of [ClassField] for input to this method.

See also the [Class.WithSyntax] method for a means of associating
alternative names (e.g.: "DESC") with base names (e.g.: "&desc")
following the successful creation of a [Class] instance.
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
	uLUT := make(map[string]map[any]*ClassInstance)
	for i := range fields {
		lut[fields[i].Label] = &fields[i]
		if fields[i].opts.Unique {
			uLUT[fields[i].Label] = make(map[any]*ClassInstance)
		}
	}
	return Class{Name: name, Fields: fields, fieldLUT: lut}, nil
}

/*
WithSyntax returns an error following an attempt to parse an instance of
map[string]string, which serves as the abstraction for the "WITH SYNTAX"
ASN.1 keyword for the purpose of associating alternative names to CLASS
fields.

The syntax for w is ALT-LABEL (key) -> AMP-LABEL (value), e.g.:

	map[string]string{
	  "DIRECTORY SYNTAX": "&Type",
	  ...
	}

A non-nil error is returned if the AMP-LABEL is not found, or if w
does not contain the exact number of keys as fields in r.

Permitted characters for an ALT-LABEL are effectively the same as
ordinary ASN.1 identifiers, except that support for SPACE is included,
so long as it is neither trailing nor leading, and is non-consecutive.
*/
func (r *Class) WithSyntax(w map[string]string) (err error) {
	lf, lw := len(r.Fields), len(w)
	if lf != lw {
		err = classErrorf("CLASS 'WITH SYNTAX' length mismatch: want ",
			lf, ", got ", lw)
		return
	}

	for k, v := range w {
		if _, found := r.Field(k); found {
			err = classErrorf("Duplicate 'WITH SYNTAX' field '", k, "'")
			break
		} else if hasPfx(k, "&") {
			err = classErrorf("Invalid 'WITH SYNTAX' field '",
				k, "': alt. label must not begin with '&'")
			break
		} else if !hasPfx(v, "&") {
			err = classErrorf("Invalid 'WITH SYNTAX' source '",
				v, "': reference must begin with '&'")
			break
		}

		field, found := r.Field(v)
		if !found {
			err = classErrorf("Unknown field '", v,
				"' in ", r.Name, " CLASS (WITH SYNTAX)")
			break
		}

		field.WithLabel = k   // register alt. name
		r.fieldLUT[k] = field // add new association to lookup table
		if field.opts.Unique {
			r.uniqueLUT[k] = make(map[any]*ClassInstance)
		}
	}

	return
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

The input label value must start with '&' and represents the base name of the
[Class] field.

The prototype value represents a concrete type to be enforced during subsequent
[ClassInstance] use, or nil if there is more than one possible concrete type.

The opts (*[Options]) variadic input allows for select parameters to be supplied,
though at the time of this writing only "Optional" (bool) has any meaning.
*/
func (k ClassFieldKind) NewField(
	label string,
	prototype any, // value that represents a fixed type, or nil if unfixed
	opts ...*Options,
) (ClassField, error) {

	if label == "" {
		return ClassField{}, classErrorf("ClassField: empty label")
	}
	if !hasPfx(label, "&") {
		return ClassField{}, classErrorf("ClassField ", label, ": must start with ‘&’")
	}

	if prototype == nil {
		prototype = dynType{}
	}

	o := deferImplicit(nil)
	if len(opts) > 0 {
		o = opts[0]
	}

	return ClassField{
		Label: label,
		Kind:  k,
		Type:  refTypeOf(prototype),
		opts:  o,
	}, nil
}

type dynType struct{} // for when a CLASS &Type is unfixed, such as with X.501 SYNTAX-NAME instances
var refDynType = refTypeOf(dynType{})
