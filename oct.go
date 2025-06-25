package asn1plus

/*
oct.go contains all types and methods pertaining to the ASN.1
OCTET STRING type.
*/

import "bytes"

/*
OctetString returns an instance of [OctetString] alongside an error
following an attempt to marshal x.
*/
func NewOctetString(x any, constraints ...Constraint[OctetString]) (oct OctetString, err error) {
	var str string

	switch tv := x.(type) {
	case []byte:
		str = string(tv)
	case string:
		str = tv
	case Primitive:
		str = tv.String()
	default:
		err = errorBadTypeForConstructor("OCTET STRING", x)
		return
	}

	_oct := OctetString(str)
	err = OctetSpec(_oct)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[OctetString] = constraints
		err = group.Validate(_oct)
	}

	if err == nil {
		oct = _oct
	}

	return
}

/*
OctetSpec implements the formal [Constraint] specification for [OctetString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var OctetSpec Constraint[OctetString]

/*
OctetString implements the ASN.1 OCTET STRING type (tag 4).
*/
type OctetString []byte

/*
Tag returns the integer constant [TagOctetString].
*/
func (r OctetString) Tag() int { return TagOctetString }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *OctetString) IsZero() bool { return r == nil }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r OctetString) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string { return string(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r OctetString) Len() int {
	var l int
	if &r != nil {
		l = len(r)
	}
	return l
}

func cerSegmentedOctetStringWrite[T TextLike](c *textCodec[T], pkt Packet, o *Options) (n int, err error) {
	const maxSegSize = 1000

	// 1. Obtain the raw "wire" data.
	var wire []byte
	if c.encodeHook != nil {
		wire, err = c.encodeHook(c.val)
	} else {
		wire = []byte(c.val)
	}

	if err == nil {
		// 2. Build the outer header manually.
		// For CER, we use a constructed OCTET STRING with indefinite length.
		// A common encoding is:
		//   Identifier: 0x04 (OCTET STRING) with constructed flag (0x20) ⇒ 0x24
		//   Length: 0x80 indicating indefinite length.
		outerHeader := []byte{0x24, 0x80}

		// 3. Build the inner segments.
		var innerBuf bytes.Buffer
		segCount := 0
		for i := 0; i < len(wire); i += maxSegSize {
			end := i + maxSegSize
			if end > len(wire) {
				end = len(wire)
			}
			segment := wire[i:end]
			// For a primitive OCTET STRING, the identifier is fixed to 0x04.
			id := byte(0x04)
			segLen := len(segment)
			var lenBytes []byte
			encodeLengthInto(pkt.Type(), &lenBytes, segLen)
			innerBuf.WriteByte(id)
			innerBuf.Write(lenBytes)
			innerBuf.Write(segment)
			segCount++
		}

		// 4. Append the EOC marker (two zero bytes).
		eocMarker := []byte{0x00, 0x00}

		// 5. Assemble the complete CER message:
		// Outer header || Inner segments || EOC marker.
		completeBuf := make([]byte, 0, len(outerHeader)+innerBuf.Len()+len(eocMarker))
		completeBuf = append(completeBuf, outerHeader...)
		completeBuf = append(completeBuf, innerBuf.Bytes()...)
		completeBuf = append(completeBuf, eocMarker...)

		// 6. Manufacture a new Packet using the provided constructor.
		rep := pkt.Type().New(completeBuf...)
		rep.SetOffset(0)

		// 7. Replace the original Packet's contents in place.
		pkt.(*CERPacket).data = rep.Data()

		n = len(completeBuf)

	}

	return
}

func cerSegmentedOctetStringRead[T TextLike](c *textCodec[T], pkt Packet, o *Options) (err error) {
	// Reset offset to 0 to start reading the complete constructed value.
	pkt.SetOffset(0)
	data := pkt.Data()
	offset := pkt.Offset()

	// 1. Read and verify the outer header.
	// Expected outer header for a constructed OCTET STRING in CER is:
	//   Identifier: 0x24 (0x04 with constructed flag 0x20)
	//   Length: 0x80 (indefinite)
	if offset+2 > len(data) {
		return mkerr("data too short for outer CER header")
	}
	outerId := data[offset]
	outerLen := data[offset+1]
	if outerId != 0x24 || outerLen != 0x80 {
		return mkerrf("outer header not as expected: got ", itoa(int(outerId)), " ", itoa(int(outerLen)))
	}
	offset += 2

	// Iterate over inner segments until
	// we encounter the EOC marker (00 00).
	var full []byte
	segIndex := 0
	for {
		// Check for EOC marker.
		if cerCheckEOC(offset, data) {
			break
		}
		if offset >= len(data) {
			return mkerrf("unexpected end-of-data while reading segment ", itoa(segIndex))
		}

		offset++
		segLen, lr, err := decodeCERLength(data, offset)
		if err != nil {
			return mkerrf("failed reading length for segment ", itoa(segIndex), ": ", err.Error())
		}
		offset += lr
		if offset+segLen > len(data) {
			return mkerrf("truncated inner TLV: value incomplete at segment ", itoa(segIndex))
		}
		segmentValue := data[offset : offset+segLen]
		offset += segLen

		full = append(full, segmentValue...)
		segIndex++
	}

	for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
		err = c.decodeVerify[i](full)
	}

	if err == nil {
		var val T
		if c.decodeHook != nil {
			val, err = c.decodeHook(full)
		} else {
			val = T(append([]byte(nil), full...))
		}

		if err == nil {
			if err = c.cg.Constrain(val); err == nil {
				c.val = val
			}
		}
	}

	return err
}

func init() {
	RegisterTextAlias[OctetString](TagOctetString, nil, nil, nil, OctetSpec)
	OctetSpec = func(o OctetString) (err error) {
		for _, r := range []rune(o.String()) {
			if r > 0x00FF {
				err = mkerrf("Invalid character '", string(r), "' (>0x00FF) in OCTET STRING")
				break
			}
		}
		return
	}
}
