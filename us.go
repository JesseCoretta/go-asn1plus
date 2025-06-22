package asn1plus

/*
us.go contains all types and methods pertaining to the ASN.1
UNIVERSAL STRING type.
*/

import "encoding/binary"

/*
UniversalString implements the UCS-4 ASN.1 UNIVERSAL STRING (tag 28).
*/
type UniversalString string

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
*/
func NewUniversalString(x any, constraints ...Constraint[UniversalString]) (UniversalString, error) {
	var (
		us  UniversalString
		raw string
		err error
	)

	switch tv := x.(type) {
	case UniversalString:
		raw = tv.String()
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = mkerr("Invalid type for ASN.1 UNIVERSAL STRING")
		return us, err
	}

	_us := UniversalString(raw)
	group := append(
		ConstraintGroup[UniversalString]{UniversalSpec}, // built-in
		constraints...)
	err = group.Validate(_us)
	if err == nil {
		us = _us
	}

	return us, err
}

/*
UniversalSpec implements the formal [Constraint] specification for [UniversalString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var UniversalSpec Constraint[UniversalString]

func universalStringDecoderVerify(b []byte) (err error) {
	if len(b)%4 != 0 {
		err = mkerr("UNIVERSAL STRING: byte length not multiple of 4")
		return
	}
	for i := 0; i < len(b); i += 4 {
		code := binary.BigEndian.Uint32(b[i:])
		if code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF) {
			err = mkerrf("UNIVERSAL STRING: invalid code point: ", itoa(int(code)))
			break
		}
	}

	return
}

// UTF-32BE -> Go string
func decodeUniversalString(b []byte) (UniversalString, error) {
	var runes []rune
	for i := 0; i < len(b); i += 4 {
		runes = append(runes, rune(binary.BigEndian.Uint32(b[i:i+4])))
	}

	return UniversalString(string(runes)), nil
}

// Go string -> UTF-32BE
func encodeUniversalString(u UniversalString) (content []byte, err error) {
	runes := []rune(u)
	content = make([]byte, 4*len(runes))
	for i := 0; i < len(runes) && err == nil; i++ {
		r := runes[i]
		if err = universalStringCharacterOutOfBounds(r); err == nil {
			binary.BigEndian.PutUint32(content[i*4:], uint32(r))
		}
	}
	return content, err
}

func universalStringCharacterOutOfBounds(r rune) (err error) {
	if r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) {
		err = mkerrf("UNIVERSAL STRING: invalid code point ", string(r), " (", itoa(int(r)), ")")
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string {
	// Fast-path: if the length isn’t a multiple of
	// 4 we *know* it can’t be UTF-32BE, so we'll
	// just cast as-is.
	if len(r)%4 != 0 {
		return string(r)
	}

	// Attempt to interpret as UTF-32BE.  If we hit an
	// invalid sequence we fall back to the raw bytes.
	runes := make([]rune, 0, len(r)/4)
	for i := 0; i+4 <= len(r); i += 4 {
		code := binary.BigEndian.Uint32([]byte(r[i:])) // has to be []byte
		runes = append(runes, rune(code))
		if universalStringCharacterOutOfBounds(rune(code)) != nil {
			// Not valid UTF-32BE; bail out to raw bytes.
			runes = []rune(string(r))
			break
		}
	}
	return string(runes)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }

func init() {
	RegisterTextAlias[UniversalString](TagUniversalString, universalStringDecoderVerify, decodeUniversalString, encodeUniversalString, UniversalSpec)
	UniversalSpec = func(us UniversalString) (err error) {
		// Reject byte sequences that are not valid UTF-8.
		if !utf8OK(string(us)) {
			return mkerr("UniversalString: input is not valid UTF-8")
		}

		// Reject surrogates and code points beyond Unicode max.
		for i := 0; i < len(us) && err == nil; i++ {
			err = universalStringCharacterOutOfBounds(rune(us[i]))
		}

		return
	}
}
