package asn1plus

/*
bmp.go contains all types and methods pertaining to the Basic Multilingual
Plane (BMP) string.
*/

/*
BMPString implements the Basic Multilingual Plane per [ITU-T Rec. X.680]
(tag 30).

The structure for instances of this type is as follows:

	T (30, Ox1E) N (NUM. BYTES) P{byte,byte,byte}

Tag T represents ASN.1 BMPSTRING tag integer 30 (0x1E). Number N is an
int-cast byte value that cannot exceed 255. The remaining bytes, which
may be zero (0) or more in number, define payload P. N must equal size
of payload P.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type BMPString []byte

/*
NewBMPString returns an instance of [BMPString] alongside an error following
an attempt to marshal x.
*/
func NewBMPString(x any, constraints ...Constraint[BMPString]) (bmp BMPString, err error) {
	var e string

	switch tv := x.(type) {
	case []uint8:
		e = string(tv)

	case BMPString:
		if err = BMPSpec(tv); err != nil {
			return
		}
		e = tv.String()

	case string:
		e = tv

	default:
		err = mkerr("Invalid type for ASN.1 BMPSTRING")
		return
	}

	if len(e) == 0 {
		bpm := BMPString{0x1E, 0x0}
		bmp = bpm
		return
	}

	var result []byte
	if result, err = buildBMP(e); err != nil {
		return
	}

	_bmp := BMPString(result)

	var group ConstraintGroup[BMPString] = append(ConstraintGroup[BMPString]{BMPSpec}, constraints...)

	if err = group.Validate(_bmp); err == nil {
		bmp = _bmp
	}
	return
}

/*
BMPSpec implements the formal [Constraint] specification for [BMPString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var BMPSpec Constraint[BMPString]

func buildBMP(e string) (out []byte, err error) {
	out = []byte{byte(TagBMPString)}

	// empty string → tag, length 0
	if len(e) == 0 {
		out = append(out, 0)
	} else {
		encoded := utf16Enc([]rune(e))
		if len(encoded) > 255 {
			err = mkerr("input string too long for BMPString encoding")
		} else {
			out = append(out, byte(len(encoded)))
			for _, ch := range encoded {
				out = append(out, byte(ch>>8), byte(ch&0xFF))
			}
		}
	}

	return
}

/*
Tag returns the integer constant [TagBMPString].
*/
func (r BMPString) Tag() int { return TagBMPString }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (r BMPString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r BMPString) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.

This involves unmarshaling the receiver into a string return value.
*/
func (r BMPString) String() string {
	var s string
	if len(r) < 3 || r[0] != 0x1E {
		return s
	}

	length := int(r[1])
	expectedLength := 2 + length*2
	if len(r) == expectedLength {
		var result []rune
		for i := 2; i < expectedLength; i += 2 {
			codePoint := (rune(r[i]) << 8) | rune(r[i+1])
			result = append(result, codePoint)
		}

		s = string(result)
	}

	return s
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BMPString) IsZero() bool { return r == nil }

func init() {
	RegisterTextAlias[BMPString](TagBMPString, nil, nil, nil, BMPSpec)
	BMPSpec = func(o BMPString) (err error) {
		if len(o) == 0 {
			return
		} else if len(o) == 2 {
			if o[0] != 0x1E || o[1] != 0x0 {
				err = mkerr("Invalid ASN.1 tag or length octet for empty string")
			}
		} else {
			if o[0] != 0x1E {
				err = mkerr("Invalid ASN.1 tag")
			} else if int(o[1])*2 != len(o[2:]) {
				err = mkerr("input string encoded length does not match length octet")
			}
		}

		return
	}
}
