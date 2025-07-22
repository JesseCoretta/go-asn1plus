package asn1plus

/*
utf8.go contains all types and methods pertaining to the ASN.1
UTF8 STRING.
*/

/*
UTF8String implements a flexible form of the ASN.1 UTF8 STRING (tag 12)
type per [ITU-T Rec. X.680].

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type UTF8String string

/*
UTF8StringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var UTF8StringConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagUTF8String].
*/
func (r UTF8String) Tag() int { return TagUTF8String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r UTF8String) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r UTF8String) Len() int { return len(r) }

/*
NewUTF8String returns an instance of [UTF8String] alongside an error following an
attempt to marshal x.

The variadic constraints input allows for any number of override closures based upon
the [Constraint] signature.

One such situation that benefits from this feature in the real world is the UTF-8 range
in [ITU-T Rec. X.680] versus the constrained UTF8String characters defined in [§ 1.4 of
RFC 4512].

By default, the [utf8.ValidString] function is used for validation.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
func NewUTF8String(x any, constraints ...Constraint) (u8 UTF8String, err error) {
	var raw string
	switch tv := x.(type) {
	case Primitive:
		raw = tv.String()
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = errorBadTypeForConstructor("UTF-8 STRING", x)
		return
	}

	if len(raw) == 0 {
		err = errorNilInput
		return
	}

	_u8 := UTF8String(raw)
	err = UTF8Spec(_u8)
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_u8)
	}

	if err == nil {
		u8 = _u8
	}

	return
}

/*
UTF8Spec implements the formal [Constraint] specification for [UTF8String].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var UTF8Spec Constraint

/*
String returns the string representation of the receiver instance.
*/
func (r UTF8String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UTF8String) IsZero() bool { return len(r) == 0 }

func init() {
	UTF8Spec = func(u8 any) (err error) {
		var o UTF8String
		switch tv := u8.(type) {
		case Primitive:
			o = UTF8String(tv.String())
		case []byte:
			o = UTF8String(tv)
		case string:
			o = UTF8String(tv)
		default:
			err = errorPrimitiveAssertionFailed(o)
			return
		}

		if !utf8OK(o.String()) {
			err = primitiveErrorf("UTF8String: invalid character(s) in input")
		}

		return
	}

	RegisterTextAlias[UTF8String](TagUTF8String,
		UTF8StringConstraintPhase,
		nil, nil, nil, UTF8Spec)
}
