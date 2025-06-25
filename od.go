package asn1plus

/*
od.go contains all types and methods pertaining to the ASN.1
OBJECT DESCRIPTOR type.
*/

/*
ObjectDescriptor implements the ASN.1 OBJECT DESCRIPTOR type (tag 7).
It operates under the same principals and constraints as the ASN.1
[GraphicString] type.
*/
type ObjectDescriptor string

/*
NewObjectDescriptor returns an instance of [ObjectDescriptor] alongside
an error following an attempt to marshal x.
*/
func NewObjectDescriptor(x any, constraints ...Constraint[ObjectDescriptor]) (ObjectDescriptor, error) {
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
		var group ConstraintGroup[ObjectDescriptor] = constraints
		err = group.Validate(_od)
	}

	if err == nil {
		od = _od
	}

	return od, err
}

/*
ObjectDescriptorSpec implements the formal [Constraint] specification for [ObjectDescriptor].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var ObjectDescriptorSpec Constraint[ObjectDescriptor]

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

func init() {
	RegisterTextAlias[ObjectDescriptor](TagObjectDescriptor, nil, nil, nil, ObjectDescriptorSpec)
	ObjectDescriptorSpec = func(o ObjectDescriptor) error {
		// ObjectDescriptor supports GRAPHIC STRING characters
		return graphicStringDecoderVerify([]byte(o))
	}
}
