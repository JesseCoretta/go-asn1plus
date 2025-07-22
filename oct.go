package asn1plus

/*
oct.go contains all types and methods pertaining to the ASN.1
OCTET STRING type.
*/

/*
OctetString returns an instance of [OctetString] alongside an error
following an attempt to marshal x.
*/
func NewOctetString(x any, constraints ...Constraint) (oct OctetString, err error) {
	var str string

	switch tv := x.(type) {
	case []byte:
		str = string(tv)
	case string:
		str = tv
	case Primitive:
		str = tv.String()
	default:
		err = errorBadTypeForConstructor("OCTET STRING", x)
		return
	}

	_oct := OctetString(str)
	err = OctetSpec(_oct)
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_oct)
	}

	if err == nil {
		oct = _oct
	}

	return
}

/*
OctetSpec implements the formal [Constraint] specification for [OctetString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var OctetSpec Constraint

/*
OctetString implements the ASN.1 OCTET STRING type (tag 4).
*/
type OctetString []byte

/*
OctetStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var OctetStringConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagOctetString].
*/
func (r OctetString) Tag() int { return TagOctetString }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *OctetString) IsZero() bool { return r == nil }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r OctetString) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string { return string(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r OctetString) Len() int {
	var l int
	if &r != nil {
		l = len(r)
	}
	return l
}

func init() {
	OctetSpec = func(oct any) (err error) {
		var o []rune
		switch tv := oct.(type) {
		case []byte:
			o = []rune(string(tv))
		case string:
			o = []rune(tv)
		case Primitive:
			o = []rune(tv.String())
		default:
			err = errorPrimitiveAssertionFailed(o)
			return
		}

		for _, r := range o {
			if r > 0x00FF {
				err = primitiveErrorf("OCTET STRING: invalid character '",
					string(r), "' (>0x00FF)")
				break
			}
		}
		return
	}

	RegisterTextAlias[OctetString](TagOctetString,
		OctetStringConstraintPhase,
		nil, nil, nil, OctetSpec)
}
