//go:build !asn1_no_dprc

package asn1plus

/*
t61.go contains all types and methods pertaining to the ASN.1
T61 STRING (also known as a teletex string).
*/

/*
Deprecated: T61String implements the [ITU-T Rec. T.61] string (tag 20).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems. Use [UniversalString], [BMPString]
or [UTF8String].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
type T61String string

/*
T61StringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var T61StringConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagT61String].
*/
func (_ T61String) Tag() int { return TagT61String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (_ T61String) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r T61String) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r T61String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r T61String) IsZero() bool { return len(r) == 0 }

/*
T61String returns an instance of [T61String] alongside an error
following an analysis of x in the context of a Teletex String, per
[ITU-T Rec. T.61].

See also [MustNewT61String].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
func NewT61String(x any, constraints ...Constraint) (T61String, error) {
	var (
		raw string
		t61 T61String
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
		err = errorBadTypeForConstructor("T.61 (Teletex) STRING", x)
		return t61, err
	}

	_t61 := T61String(raw)
	err = T61Spec(_t61)
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_t61)
	}

	if err == nil {
		t61 = _t61
	}

	return t61, err
}

/*
MustNewT61String returns an instance of [T61String] and
panics if [NewT61String] returned an error during processing
of x.
*/
func MustNewT61String(x any, constraints ...Constraint) T61String {
	b, err := NewT61String(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

/*
T61Spec implements the formal [Constraint] specification for [T61String].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var T61Spec Constraint

var t61Bitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			t61Bitmap[r>>6] |= 1 << (r & 63)
		}
	}
	set(0x0009, 0x000f)
	set(0x0020, 0x0039)
	set(0x0041, 0x005B)
	set(0x0061, 0x007A)
	set(0x00A0, 0x00FF)
	set(0x008B, 0x008C)
	set(0x0126, 0x0127)
	set(0x0131, 0x0132)
	set(0x0140, 0x0142)
	set(0x0149, 0x014A)
	set(0x0152, 0x0153)
	set(0x0166, 0x0167)
	set(0x0300, 0x0304)
	set(0x0306, 0x0308)
	set(0x030A, 0x030C)
	set(0x0327, 0x0328)
	set(0x009B, 0x009B)
	set(0x005C, 0x005C)
	set(0x005D, 0x005D)
	set(0x005F, 0x005F)
	set(0x003F, 0x003F)
	set(0x007C, 0x007C)
	set(0x007F, 0x007F)
	set(0x001D, 0x001D)
	set(0x0111, 0x0111)
	set(0x0138, 0x0138)
	set(0x0332, 0x0332)
	set(0x2126, 0x2126)
	set(0x013F, 0x013F)
	set(0x014B, 0x014B)

	T61Spec = func(t61 any) (err error) {
		var o []rune
		switch tv := t61.(type) {
		case string:
			o = []rune(tv)
		case []byte:
			o = []rune(string(tv))
		case Primitive:
			o = []rune(tv.String())
		default:
			err = errorPrimitiveAssertionFailed(T61String(``))
			return
		}

		if len(o) == 0 {
			err = primitiveErrorf("T61String is zero length")
			return
		}

		isT61Char := func(ch rune) (is bool) {
			if !(ch < 0 || ch > 0xFFFF) {
				word := ch >> 6
				bit := ch & 63
				is = (t61Bitmap[word]>>bit)&1 != 0
			}
			return
		}

		for _, r := range o {
			if !isT61Char(r) {
				err = primitiveErrorf("T61String: invalid character '", int(r), "'")
				break
			}
		}

		return
	}

	RegisterTextAlias[T61String](TagT61String,
		T61StringConstraintPhase,
		nil, nil, nil, T61Spec)
}
