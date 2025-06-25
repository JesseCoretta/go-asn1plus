package asn1plus

/*
gen.go contains all types and methods pertaining to the ASN.1
GENERAL STRING type.
*/

/*
Deprecated: GeneralString implements the ASN.1 GENERAL STRING type (tag 27).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type GeneralString string

/*
NewGeneralString returns an instance of [GeneralString] alongside an error
following attempt to marshal x.
*/
func NewGeneralString(x any, constraints ...Constraint[GeneralString]) (gen GeneralString, err error) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case Primitive:
		s = tv.String()
	default:
		err = errorBadTypeForConstructor("GENERAL STRING", x)
		return
	}

	_gen := GeneralString(s)
	err = GeneralSpec(_gen)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[GeneralString] = constraints
		err = group.Validate(_gen)
	}

	if err == nil {
		gen = _gen
	}

	return
}

/*
GeneralSpec implements the formal [Constraint] specification for [GeneralString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var GeneralSpec Constraint[GeneralString]

/*
Len returns the integer byte length of the receiver instance.
*/
func (r GeneralString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r GeneralString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralString) String() string { return string(r) }

/*
Tag returns the ASN.1 tag for GeneralString.
*/
func (r GeneralString) Tag() int { return TagGeneralString }

/*
IsPrimitive returns true, indicating that the receiver instance is
a known ASN.1 primitive.
*/
func (r GeneralString) IsPrimitive() bool { return true }

var generalStringBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	RegisterTextAlias[GeneralString](TagGeneralString, nil, nil, nil, GeneralSpec)
	GeneralSpec = func(o GeneralString) (err error) {
		runes := []rune(o.String())
		for i := 0; i < len(runes) && err == nil; i++ {
			r := rune(runes[i])
			word := r >> 6
			bit := r & 63

			if (generalStringBitmap[word]>>bit)&1 == 0 {
				err = mkerrf("Invalid character '", string(r), "' (<0x0000 | >0xFFFF) in GENERAL STRING")
			}
		}

		return
	}

	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			generalStringBitmap[r>>6] |= 1 << (r & 63)
		}
	}
	// 0x0000..0x007F: Basic Latin (includes control characters)
	// 0x0080..0x009F: C1 Controls (rarely printable but part of the charset)
	// 0x00A0..0x00FF: Latin‑1 Supplement (graphical characters)
	set(0x0000, 0x00FF)
}
