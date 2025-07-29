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

Note that this type may not be "string cast friendly", as it requires
specific byte composition involving the tag and UTF-16-centric length
octets.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type BMPString []byte

/*
BMPStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var BMPStringConstraintPhase = CodecConstraintDecoding

/*
NewBMPString returns an instance of [BMPString] alongside an error following
an attempt to marshal x.
*/
func NewBMPString(x any, constraints ...Constraint) (bmp BMPString, err error) {
	if tv, ok := x.(BMPString); ok {
		if len(tv) == 0 {
			bmp = BMPString{byte(TagBMPString), 0x00}
			return
		}
		if err = BMPSpec(tv); err != nil {
			return
		}
		bmp = tv
		return
	}

	var e string
	switch tv := x.(type) {
	case []byte:
		e = string(tv)
	case Primitive:
		e = tv.String()
	case string:
		e = tv
	default:
		err = errorBadTypeForConstructor("BMP STRING", x)
		return
	}

	if len(e) == 0 {
		return BMPString{byte(TagBMPString), 0x00}, nil
	}

	var out []byte
	if out, err = buildBMP(e); err != nil {
		return
	}

	_bmp := BMPString(out)

	var group ConstraintGroup = constraints
	if err = group.Constrain(_bmp); err == nil {
		bmp = _bmp
	}
	return
}

func buildBMP(e string) ([]byte, error) {
	// TagBMPString=0x1E, maxUnits=255, maxBPU=4 bytes (surrogate pairs)
	return buildText(e, TagBMPString, 255, 4, func(r rune, dst []byte, pos int) (bw, cu int, err error) {
		if r <= 0xFFFF {
			dst[pos], dst[pos+1] = byte(r>>8), byte(r)
			return 2, 1, nil
		}
		v := r - 0x10000
		hi := 0xD800 | (v >> 10)
		lo := 0xDC00 | (v & 0x3FF)
		dst[pos], dst[pos+1] = byte(hi>>8), byte(hi)
		dst[pos+2], dst[pos+3] = byte(lo>>8), byte(lo)
		return 4, 2, nil
	})
}

/*
BMPSpec implements the formal [Constraint] specification for [BMPString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var BMPSpec Constraint

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
	if len(r) < 3 || r[0] != byte(TagBMPString) {
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
	BMPSpec = func(bmp any) (err error) {
		var o BMPString
		switch tv := bmp.(type) {
		case string:
			o, _ = NewBMPString(tv)
		case BMPString:
			o = tv // as-is
		case Primitive:
			o, _ = NewBMPString(tv)
		default:
			err = errorPrimitiveAssertionFailed(o)
			return
		}

		if len(o) == 0 {
			return
		} else if len(o) == 2 {
			if o[0] != byte(TagBMPString) || o[1] != 0x0 {
				err = primitiveErrorf("BMPString: invalid ASN.1 tag or length octet for empty string")
			}
		} else {
			if o[0] != byte(TagBMPString) {
				err = primitiveErrorf("BMPString: Invalid ASN.1 tag")
			} else if int(o[1])*2 != len(o[2:]) {
				err = primitiveErrorf("BMPString: input string encoded length does not match length octet")
			}
		}

		return
	}

	RegisterTextAlias[BMPString](TagBMPString,
		BMPStringConstraintPhase,
		nil, nil, nil, BMPSpec)
}
