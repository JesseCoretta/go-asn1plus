package asn1plus

/*
od.go contains all types and methods pertaining to the ASN.1
OBJECT DESCRIPTOR type.
*/

import "unicode"

/*
ObjectDescriptor implements the ASN.1 OBJECT DESCRIPTOR type (tag 7).
It operates under the same principals and constraints as the ASN.1
[GraphicString] type.
*/
type ObjectDescriptor string

/*
ObjectDescriptorConstraintPhase declares the appropriate phase
for the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var ObjectDescriptorConstraintPhase = CodecConstraintDecoding

/*
NewObjectDescriptor returns an instance of [ObjectDescriptor] alongside
an error following an attempt to marshal x.

See also [MustNewObjectDescriptor].
*/
func NewObjectDescriptor(x any, constraints ...Constraint) (ObjectDescriptor, error) {
	var (
		str string
		od  ObjectDescriptor
		err error
	)

	switch tv := x.(type) {
	case string:
		str = tv
	case []byte:
		str = string(tv)
	case Primitive:
		str = tv.String()
	default:
		err = errorBadTypeForConstructor("OBJECT DESCRIPTOR", x)
		return od, err
	}

	_od := ObjectDescriptor(str)
	err = ObjectDescriptorSpec(_od)
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_od)
	}

	if err == nil {
		od = _od
	}

	return od, err
}

/*
MustNewObjectDescriptor returns an instance of [ObjectDescriptor] and
panics if [NewObjectDescriptor] returned an error during processing
of x.
*/
func MustNewObjectDescriptor(x any, constraints ...Constraint) ObjectDescriptor {
	b, err := NewObjectDescriptor(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

/*
ObjectDescriptorSpec implements the formal [Constraint] specification
for [ObjectDescriptor].

Note that this specification is automatically executed during construction
and need not be specified manually as a [Constraint] by the end user.
*/
var ObjectDescriptorSpec Constraint

/*
Len returns the integer length of the receiver instance.
*/
func (r ObjectDescriptor) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectDescriptor) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectDescriptor) String() string { return string(r) }

/*
Tag returns the integer constant [TagObjectDescriptor].
*/
func (r ObjectDescriptor) Tag() int { return TagObjectDescriptor }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r ObjectDescriptor) IsPrimitive() bool { return true }

func graphicStringDecoderVerify(b []byte) (err error) {
	runes := []rune(string(b))
	for i := 0; i < len(runes) && err == nil; i++ {
		ch := rune(runes[i])
		if !unicode.IsPrint(ch) || unicode.IsControl(ch) || (ch < 128 && !(32 <= ch && ch <= 126)) {
			err = primitiveErrorf("GraphicString: invalid character: ", string(ch))
		}
	}
	return
}

func init() {
	ObjectDescriptorSpec = func(obj any) (err error) {
		switch tv := obj.(type) {
		case string:
			err = graphicStringDecoderVerify([]byte(tv))
		case []byte:
			err = graphicStringDecoderVerify(tv)
		case Primitive:
			err = graphicStringDecoderVerify([]byte(tv.String()))
		default:
			err = errorPrimitiveAssertionFailed(ObjectDescriptor(``))
		}
		return
	}

	RegisterTextAlias[ObjectDescriptor](TagObjectDescriptor,
		ObjectDescriptorConstraintPhase,
		nil, nil, nil, ObjectDescriptorSpec)
}
