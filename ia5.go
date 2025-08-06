package asn1plus

/*
ia5.go contains all types and methods pertaining to the International
Alphabet No. 5 string.
*/

/*
IA5String implements the [ITU-T Rec. T.50] IA5 string (tag 22), supporting
the following character range from the International Alphabet No. 5:

	0x00 through 0xFF

[ITU-T Rec. T.50]: https://www.itu.int/rec/T-REC-T.50
*/
type IA5String string

/*
IA5StringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var IA5StringConstraintPhase = CodecConstraintDecoding

/*
Len returns the integer length of the receiver instance.
*/
func (r IA5String) Len() int { return len(r) }

/*
Tag returns the integer constant [TagIA5String].
*/
func (r IA5String) Tag() int { return TagIA5String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive type.
*/
func (r IA5String) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r IA5String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r IA5String) IsZero() bool { return len(r) == 0 }

/*
IA5String returns an instance of [IA5String] alongside an error following
an attempt to marshal x.

See also [MustNewIA5String].
*/
func NewIA5String(x any, constraints ...Constraint) (IA5String, error) {
	var (
		ia5 IA5String
		err error
	)

	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case Primitive:
		raw = tv.String()
	default:
		err = errorBadTypeForConstructor("IA5 STRING", x)
		return ia5, err
	}

	_ia5 := IA5String(raw)
	err = IA5Spec(_ia5)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup = constraints
		err = group.Constrain(_ia5)
	}

	if err == nil {
		ia5 = _ia5
	}

	return ia5, err
}

/*
MustNewIA5String returns an instance of [IA5String] and
panics if [NewIA5String] returned an error during processing
of x.
*/
func MustNewIA5String(x any, constraints ...Constraint) IA5String {
	b, err := NewIA5String(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

/*
IA5Spec implements the formal [Constraint] specification for [IA5String].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var IA5Spec Constraint

func init() {
	IA5Spec = func(ia5 any) (err error) {
		var o IA5String
		switch tv := ia5.(type) {
		case string:
			o = IA5String(tv)
		case Primitive:
			o = IA5String(tv.String())
		default:
			err = errorPrimitiveAssertionFailed(o)
			return
		}
		if len(o) == 0 {
			err = primitiveErrorf("IA5 String: zero")
			return
		}

		runes := []rune(o.String())
		for i := 0; i < len(runes) && err == nil; i++ {
			var char rune = runes[i]
			if !(0x0000 <= char && char <= 0x00FF) {
				err = primitiveErrorf("IA5 String: invalid character ", string(char))
			}
		}

		return
	}

	RegisterTextAlias[IA5String](TagIA5String,
		IA5StringConstraintPhase,
		nil, nil, nil, IA5Spec)
}
