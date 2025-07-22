//go:build !asn1_no_dprc

package asn1plus

/*
vts.go contains all types and methods pertaining to the ASN.1
VIDEOTEX STRING type.
*/

import (
	"unicode/utf8"
	"unsafe"
)

/*
Deprecated: VideotexString implements the ASN.1 VIDEOTEX STRING type (tag 21)
per ITU-T T-Series Recommendations [T.100] and [T.101].

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.

[T.100]: https://www.itu.int/rec/T-REC-T.100
[T.101]: https://www.itu.int/rec/T-REC-T.101
*/
type VideotexString string

/*
VideotexStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var VideotexStringConstraintPhase = CodecConstraintDecoding

/*
NewVideotexString returns an instance of [VideotexString] alongside an
error following an attempt to marshal x.
*/
func NewVideotexString(x any, constraints ...Constraint) (VideotexString, error) {
	var (
		raw string
		err error
		vts VideotexString
	)

	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case Primitive:
		raw = tv.String()
	default:
		err = errorBadTypeForConstructor("VIDEOTEX STRING", x)
		return vts, err
	}

	_vts := VideotexString(raw)
	err = VideotexSpec(_vts)
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_vts)
	}

	if err == nil {
		vts = _vts
	}

	return vts, err
}

/*
Len returns the integer length of the receiver instance.
*/
func (r VideotexString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r VideotexString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r VideotexString) String() string { return string(r) }

/*
Tag returns the integer constant [TagVideotexString].
*/
func (r VideotexString) Tag() int { return TagVideotexString }

/*
IsPrimitive returns true, indicative the receiver is a known
ASN.1 primitive.
*/
func (r VideotexString) IsPrimitive() bool { return true }

/*
VideotexSpec implements the formal [Constraint] specification for [VideotexString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var VideotexSpec Constraint

func isVideotexRune(ch rune) bool {
	if ch < 0 || ch > 0xFFFF { // we only built the BMP bitmap
		return false
	}
	word := ch >> 6
	bit := ch & 63
	return (videotexBitmap[word]>>bit)&1 != 0
}

func videotexDecoderVerify(b []byte) error {
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError || !isVideotexRune(r) {
			return primitiveErrorf("VideotexString: invalid character(s) in input")
		}
		i += n
	}
	return nil
}

func videotexDecoder(b []byte) (VideotexString, error) {
	return VideotexString(unsafe.String(&b[0], len(b))), nil
}

var videotexBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			videotexBitmap[r>>6] |= 1 << (r & 63)
		}
	}

	set(0x0020, 0x007E) // ASCII (including SPACE)
	set(0x00A0, 0x00FF) // Latin‑1 Supplement
	set(0x0100, 0x017F) // Latin Extended-A
	set(0x0180, 0x024F) // Latin Extended-B
	set(0x0370, 0x03FF) // Greek
	set(0x0400, 0x04FF) // Cyrillic
	set(0x0530, 0x058F) // Armenian
	set(0x0590, 0x05FF) // Hebrew
	set(0x0600, 0x06FF) // Arabic
	set(0x2500, 0x257F) // Box drawing
	set(0x2580, 0x259F) // Blocks
	set(0x25A0, 0x25FF) // Geometric shapes
	set(0x2600, 0x26FF) // Misc symbols
	set(0x2700, 0x27BF) // Dingbats
	set(0x3000, 0x303F) // CJK symbols
	set(0x4E00, 0x9FFF) // Common CJK Unified Ideographs (for Japanese Kanji or Chinese characters)

	VideotexSpec = func(vs any) (err error) {
		var o []rune
		switch tv := vs.(type) {
		case string:
			o = []rune(tv)
		case []byte:
			o = []rune(string(tv))
		case Primitive:
			o = []rune(tv.String())
		default:
			err = errorPrimitiveAssertionFailed(VideotexString(``))
			return
		}

		for _, r := range o {
			if !isVideotexRune(r) {
				err = primitiveErrorf("VideotexString: invalid character '", int(r), "'")
				break
			}
		}

		return
	}

	RegisterTextAlias[VideotexString](TagVideotexString,
		VideotexStringConstraintPhase,
		videotexDecoderVerify,
		videotexDecoder, nil,
		VideotexSpec)
}
