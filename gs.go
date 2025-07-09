//go:build !asn1_no_dprc

package asn1plus

/*
gs.go contains all types and methods pertaining to the ASN.1
GRAPHIC STRING type.
*/

/*
Deprecated: GraphicString implements the ASN.1 GRAPHIC STRING type (tag 25).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type GraphicString string

/*
GraphicStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var GraphicStringConstraintPhase = CodecConstraintDecoding

/*
NewGraphicString returns an instance of [GraphicString] alongside an error
following attempt to marshal x.
*/
func NewGraphicString(x any, constraints ...Constraint[GraphicString]) (gs GraphicString, err error) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case Primitive:
		s = tv.String()
	default:
		err = errorBadTypeForConstructor("GRAPHIC STRING", x)
		return
	}

	_gs := GraphicString(s)
	err = GraphicSpec(_gs)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[GraphicString] = constraints
		err = group.Constrain(_gs)
	}

	if err == nil {
		gs = _gs
	}

	return
}

/*
GraphicSpec implements the formal [Constraint] specification for [GraphicString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var GraphicSpec Constraint[GraphicString]

/*
Len returns the integer byte length of the receiver instance.
*/
func (r GraphicString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r GraphicString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r GraphicString) String() string { return string(r) }

/*
Tag returns the integer constant [TagGraphicString].
*/
func (r GraphicString) Tag() int { return TagGraphicString }

/*
IsPrimitive returns true, indicating the receiver instance is a
known ASN.1 primitive.
*/
func (r GraphicString) IsPrimitive() bool { return true }

func init() {
	RegisterTextAlias[GraphicString](TagGraphicString,
		GraphicStringConstraintPhase,
		graphicStringDecoderVerify,
		nil, nil, GraphicSpec)
	GraphicSpec = func(o GraphicString) error {
		return graphicStringDecoderVerify([]byte(o))
	}
}
