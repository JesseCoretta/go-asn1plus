package asn1plus

/*
cer.go contains CER-focused components. See also ber.go and der.go.
*/

import "sync"

/*
CERPacket encapsulates an [ITU-T Rec. X.690] CER-encoded byte
slice and an offset. It extends from [BERPacket].

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
type CERPacket BERPacket

/*
Type returns [CER], identifying the receiver as an ASN.1 Distinguished Encoding
Rules [Packet] qualifier.
*/
func (r CERPacket) Type() EncodingRule { return CER }

/*
Class returns an integer alongside an error following an attempt to parse
the outermost class identifier present within the underlying receiver buffer.
*/
func (r CERPacket) Class() (int, error) { return getPacketClass(&r) }

/*
Tag returns an integer alongside an error following an attempt to parse
the outermost tag identifier present within the underlying receiver buffer.
*/
func (r CERPacket) Tag() (int, error) { return getPacketTag(&r) }

/*
Compound returns a Boolean alongside an error following an attempt to parse the
outermost compound identifier present within the underlying receiver buffer.
*/
func (r CERPacket) Compound() (bool, error) { return getPacketCompound(&r) }

/*
Bytes returns the "body" of the underlying buffer alongside an error following an attempt
to extract all but the outermost header information (omit class, tag, etc.) up to and not
including the next payload.
*/
func (r CERPacket) Bytes() ([]byte, error) {
	return parseBody(r.Data(), r.Offset(), r.Type())
}

/*
FullBytes returns a byte slice representing data[:offset].
*/
func (r CERPacket) FullBytes() ([]byte, error) {
	return parseFullBytes(r.Data(), r.Offset(), r.Type())
}

/*
Hex returns the hexadecimal encoding of the underlying encoded value
within the receiver instance.
*/
func (r CERPacket) Hex() string { return formatHex(&r) }

/*
Len returns the integer length of the underlying byte buffer within
the receiver instance.
*/
func (r CERPacket) Len() int { return len(r.data) }

/*
HasMoreData returns a Boolean value indicative of whether there are more bytes remaining
to be processed.
*/
func (r CERPacket) HasMoreData() bool { return r.offset < r.Len() }

/*
Data returns the underlying byte slice.
*/
func (r *CERPacket) Data() []byte { return r.data }

/*
Append appends data to the receiver instance.
*/
func (r *CERPacket) Append(data ...byte) {
	if r == nil || len(data) == 0 {
		return
	}
	need := r.Len() + len(data)

	if cap(r.data) < need {
		bufPtr := bufPool.Get().(*[]byte)
		if cap(*bufPtr) < need {
			*bufPtr = make([]byte, 0, need*2)
		}
		newBuf := append((*bufPtr)[:0], r.data...)

		if cap(r.data) != 0 {
			old := r.data[:0]
			bufPool.Put(&old)
		}
		r.data = newBuf
	}

	r.data = append(r.data, data...)
}

/*
Offset returns the current offset position index of the underlying value within the receiver
instance.
*/
func (r *CERPacket) Offset() int { return r.offset }

/*
SetOffset replaces the current offset position index of the underlying value within the receiver
instance with a user-supplied value.

This method is intended for use in special cases where a particular packet may need to be re-read
for some reason.

Supplying an integer of negative one (-1) will set the offset to the final character in the
underlying buffer if non-zero in length.

If no variadic input is provided,, the offset position index is set to zero (0).
*/
func (r *CERPacket) SetOffset(offset ...int) { setPacketOffset(r, offset...) }

/*
Free frees the receiver instance.
*/
func (r *CERPacket) Free() {
	if cap(r.data) != 0 {
		buf := r.data[:0]
		bufPool.Put(&buf)
	}
	*r = CERPacket{}
	cerPktPool.Put(r)
}

/*
PeekTLV returns [TLV] alongside an error. This method is similar to the standard
[Packet.TLV] method, except this method does not advance the offset.
*/
func (r *CERPacket) PeekTLV() (TLV, error) {
	sub := r.Type().New(r.Data()...)
	sub.SetOffset(r.Offset())
	return getTLV(sub, nil)
}

/*
TLV returns an instance of [TLV] alongside an error following an attempt
to read the next [CER] tag/length header.
*/
func (r *CERPacket) TLV() (TLV, error) { return getTLV(r, nil) }

/*
WriteTLV returns an int following an attempt to write a [CER] tag/length
header to the receiver buffer.
*/
func (r *CERPacket) WriteTLV(tlv TLV) error { return writeTLV(r, tlv, nil) }

/*
Packet returns an instance of [Packet] alongside an error following an attempt to read
the next L (length) bytes from the receiver instance into the return [Packet].

This method is used in cases where a constructed type, i.e.: a SEQUENCE (struct), resides
within another constructed type via nesting.

Note that successful use of this method shall advance the offset to the end of the extracted
[Packet] (position offset+length). The receiver offset is not modified.
*/
func (r *CERPacket) Packet(L int) (Packet, error) { return extractPacket(r, L) }

func encodeCERLengthInto(dst *[]byte, n int) {
	if n < 128 { // short form
		*dst = append(*dst, byte(n))
		return
	}

	// long form – emit the *minimal* number of octets
	var tmp [8]byte // handles 64-bit length
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	*dst = append(*dst, 0x80|byte(len(tmp)-i))
	*dst = append(*dst, tmp[i:]...)
}

func decodeCERLength(data []byte, offset int) (length int, bytesRead int, err error) {
	if offset >= len(data) {
		return 0, 0, mkerr("no length byte available")
	}
	first := data[offset]
	offset++
	bytesRead = 1
	if first&0x80 == 0 {
		// Short form: one byte length.
		return int(first), bytesRead, nil
	}
	// Long form: the lower 7 bits tell us how many octets follow.
	numOctets := int(first & 0x7F)
	if offset+numOctets > len(data) {
		return 0, 0, mkerrf("insufficient length bytes: need ", itoa(numOctets))
	}
	length = 0
	for i := 0; i < numOctets; i++ {
		length = (length << 8) | int(data[offset+i])
	}
	bytesRead += numOctets
	return length, bytesRead, nil
}

func newCERPacket(src ...byte) (pkt Packet) {
	b := cerPktPool.Get().(*CERPacket)

	if cap(b.data) < len(src) {
		bufPtr := bufPool.Get().(*[]byte)
		if cap(*bufPtr) < len(src) {
			*bufPtr = make([]byte, 0, roundup(len(src)))
		}
		b.data = *bufPtr
	}

	b.data = append(b.data[:0], src...)
	pkt = b
	return
}

/*
// NOT NEEDED FOR NOW.
func cerCheckEOC(offset int, data []byte) (ok bool) {
	return offset+2 <= len(data) && data[offset] == 0x00 && data[offset+1] == 0x00
}
*/

var cerPktPool = sync.Pool{New: func() any { return &CERPacket{} }}
