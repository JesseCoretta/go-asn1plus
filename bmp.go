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
		if len(tv) == 0 {
			break // will fall through to produce a zero-length BMPString.
		} else if len(tv) == 2 {
			if tv[0] != 0x1E || tv[1] != 0x0 {
				err = mkerr("Invalid ASN.1 tag or length octet for empty string")
			} else {
				bmp = BMPString{0x1E, 0x0}
			}
			return
		} else {
			if tv[0] != 0x1E {
				err = mkerr("Invalid ASN.1 tag")
				return
			} else if int(tv[1])*2 != len(tv[2:]) {
				err = mkerr("input string encoded length does not match length octet")
				return
			}
			// **Decode the existing BMPString into a Go string**
			e = tv.String()
		}
	case string:
		e = tv
	default:
		err = mkerr("Invalid type for ASN.1 BMPSTRING")
		return
	}

	if len(e) == 0 {
		// Zero length values are OK
		bmp = BMPString{0x1E, 0x0}
		return
	}

	var result []byte
	result = append(result, byte(TagBMPString))

	encoded := utf16Enc([]rune(e))
	length := len(encoded)
	if uint16(length) > uint16(255) {
		err = mkerr("input string too long for BMPString encoding")
		return
	}
	result = append(result, byte(length))

	for _, char := range encoded {
		result = append(result, byte(char>>8), byte(char&0xFF))
	}

	if len(constraints) > 0 {
		var group ConstraintGroup[BMPString] = constraints
		err = group.Validate(BMPString(result))
	}

	if err == nil {
		bmp = BMPString(result)
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

func (r BMPString) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, r.Len(), false, []byte(r)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}

	return
}

func (r *BMPString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			var lt int = tlv.Length
			if pkt.Offset()+lt > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+lt, pkt.Len(), "Length")
			} else {
				*r = BMPString(data)
				pkt.SetOffset(pkt.Offset() + lt)
			}
		}
	}

	return
}
