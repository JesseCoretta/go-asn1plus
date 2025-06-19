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
*/
func NewIA5String(x any, constraints ...Constraint[IA5String]) (ia5 IA5String, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case IA5String:
		raw = tv.String()
	default:
		err = mkerr("Invalid type for IA5String")
		return
	}

	_ia5 := IA5String(raw)
	err = IA5Spec(_ia5)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[IA5String] = constraints
		err = group.Validate(_ia5)
	}

	if err == nil {
		ia5 = _ia5
	}

	return
}

/*
IA5Spec implements the formal [Constraint] specification for [IA5String].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var IA5Spec Constraint[IA5String]

func init() {
	RegisterTextAlias[IA5String](TagIA5String, nil, nil, nil, IA5Spec)
	IA5Spec = func(o IA5String) (err error) {
		if len(o) == 0 {
			err = mkerr("Invalid IA5 String (zero)")
			return
		}

		runes := []rune(o.String())
		for i := 0; i < len(runes) && err == nil; i++ {
			var char rune = runes[i]
			if !(0x0000 <= char && char <= 0x00FF) {
				err = mkerrf("Invalid IA5 String character: ", string(char))
			}
		}

		return
	}
}
