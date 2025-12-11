package asn1plus

/*
us.go contains all types and methods pertaining to the ASN.1
UNIVERSAL STRING type.
*/

import (
	"encoding/binary"
	"unicode/utf8"
)

/*
UniversalString implements the UCS-4 ASN.1 UNIVERSAL STRING (tag 28).
*/
type UniversalString string

/*
UniversalStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var UniversalStringConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagUniversalString].
*/
func (r UniversalString) Tag() int { return TagUniversalString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r UniversalString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r UniversalString) Len() int { return len(r) }

/*
NewUniversalString returns an instance of [UniversalString] alongside an
error following an attempt to marshal x.

See also [MustNewUniversalString].
*/
func NewUniversalString(x any, constraints ...Constraint) (UniversalString, error) {
	var (
		us  UniversalString
		raw string
		err error
	)

	switch tv := x.(type) {
	case Primitive:
		raw = tv.String()
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = errorBadTypeForConstructor("UNIVERSAL STRING", x)
		return us, err
	}

	_us := UniversalString(raw)
	group := append(
		ConstraintGroup{UniversalSpec}, // built-in
		constraints...)
	if err = group.Constrain(_us); err == nil {
		us = _us
	}

	return us, err
}

/*
MustNewUniversalString returns an instance of [UniversalString] and
panics if [NewUniversalString] returned an error during processing
of x.
*/
func MustNewUniversalString(x any, constraints ...Constraint) UniversalString {
	b, err := NewUniversalString(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

/*
UniversalSpec implements the formal [Constraint] specification for [UniversalString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var UniversalSpec Constraint

func universalStringDecoderVerify(b []byte) (err error) {
	if len(b)%4 != 0 {
		err = primitiveErrorf("UNIVERSAL STRING: byte length not multiple of 4")
		return
	}
	for i := 0; i < len(b); i += 4 {
		code := binary.BigEndian.Uint32(b[i:])
		if code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF) {
			err = primitiveErrorf("UNIVERSAL STRING: invalid code point: ", int(code))
			break
		}
	}

	return
}

// UTF-32BE -> Go string
func decodeUniversalString(b []byte) (UniversalString, error) {
	units := len(b) / 4
	sb := newStrBuilder()
	sb.Grow(units * 3)

	var err error
	for i := 0; i < len(b); i += 4 {
		cp := uint32(b[i])<<24 |
			uint32(b[i+1])<<16 |
			uint32(b[i+2])<<8 |
			uint32(b[i+3])
		if err = universalStringCharacterOutOfBounds(rune(cp)); err == nil {
			var tmp [4]byte
			n := utf8.EncodeRune(tmp[:], rune(cp))
			sb.Write(tmp[:n])
		}
	}
	return UniversalString(sb.String()), err
}

// Go string -> UTF-32BE
func encodeUniversalString(u UniversalString) ([]byte, error) {
	s := string(u)

	out := make([]byte, 4*len(s))
	pos := 0

	var err error
	for i := 0; i < len(s); {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && sz == 1 {
			return nil, primitiveErrorf("UniversalString: invalid UTF-8")
		}
		if err = universalStringCharacterOutOfBounds(r); err == nil {
			binary.BigEndian.PutUint32(out[pos:], uint32(r))
			pos += 4
			i += sz
		}
	}

	return out[:pos], err
}

func universalStringCharacterOutOfBounds(r rune) (err error) {
	if r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) {
		err = primitiveErrorf("UNIVERSAL STRING: invalid code point ",
			string(r), " (", int(r), ")")
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string {
	b := []byte(r)
	if len(b)%4 != 0 {
		return string(b)
	}
	sb := newStrBuilder()
	units := len(b) / 4
	sb.Grow(units * 3)
	for i := 0; i < len(b); i += 4 {
		cp := uint32(b[i])<<24 | uint32(b[i+1])<<16 |
			uint32(b[i+2])<<8 | uint32(b[i+3])
		if cp > 0x10FFFF || (0xD800 <= cp && cp <= 0xDFFF) {
			return string(b)
		}
		sb.WriteRune(rune(cp))
	}
	return sb.String()
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }

func init() {
	UniversalSpec = func(us any) (err error) {
		var o string
		switch tv := us.(type) {
		case Primitive:
			o = tv.String()
		case []byte:
			o = string(tv)
		case string:
			o = tv
		default:
			err = errorPrimitiveAssertionFailed(UniversalString(``))
			return
		}

		// Reject byte sequences that are not valid UTF-8.
		if !utf8OK(string(o)) {
			return primitiveErrorf("UniversalString: input is not valid UTF-8")
		}

		// Reject surrogates and code points beyond Unicode max.
		runes := []rune(o)
		for i := 0; i < len(runes) && err == nil; i++ {
			err = universalStringCharacterOutOfBounds(runes[i])
		}

		return
	}

	RegisterTextAlias[UniversalString](TagUniversalString,
		UniversalStringConstraintPhase,
		universalStringDecoderVerify,
		decodeUniversalString,
		encodeUniversalString,
		UniversalSpec)
}
