package asn1plus

/*
vs.go contains all types and methods pertaining to the ASN.1
VISIBLE STRING type.
*/

/*
VisibleString implements the ASN.1 VISIBLE STRING type (tag 26).
Instances of this type may contain any ASCII characters which are
not control characters.
*/
type VisibleString string

/*
VisibleStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var VisibleStringConstraintPhase = CodecConstraintDecoding

/*
NewVisibleString returns an instance of [VisibleString] alongside
an error following an attempt to marshal x.
*/
func NewVisibleString(x any, constraints ...Constraint[VisibleString]) (VisibleString, error) {
	var (
		vs  VisibleString
		raw string
		err error
	)

	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case Primitive:
		raw = tv.String()
	default:
		err = errorBadTypeForConstructor("VISIBLE STRING", x)
		return vs, err
	}

	_vs := VisibleString(raw)
	err = VisibleSpec(_vs)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[VisibleString] = constraints
		err = group.Constrain(_vs)
	}

	if err == nil {
		vs = _vs
	}

	return vs, err
}

/*
VisibleSpec implements the formal [Constraint] specification for [VisibleString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var VisibleSpec Constraint[VisibleString]

/*
Len returns the integer length of the receiver instance.
*/
func (r VisibleString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *VisibleString) IsZero() bool { return &r == nil }

/*
String returns the string representation of the receiver instance.
*/
func (r VisibleString) String() string { return string(r) }

/*
Tag returns the integer constant [TagVisibleString].
*/
func (r VisibleString) Tag() int { return TagVisibleString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r VisibleString) IsPrimitive() bool { return true }

func init() {
	RegisterTextAlias[VisibleString](TagVisibleString,
		VisibleStringConstraintPhase,
		nil, nil, nil, VisibleSpec)

	VisibleSpec = func(o VisibleString) (err error) {
		for _, r := range []rune(o.String()) {
			if r < 128 {
				if r < 32 || r > 126 || !isPrint(r) || isCtrl(r) {
					err = primitiveErrorf("Invalid character for ASN.1 VISIBLE STRING: #",
						int(r), " (is control character)")
					break
				}
			}
		}

		return
	}
}
