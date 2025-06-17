package asn1plus

/*
ber.go contains BER-focused components. See also der.go.
*/

import "sync"

/*
BERPacket implements a data encapsulation and transport type to store
[ITU-T Rec. X.690] [BER]-encoded content. It qualifies the [Packet]
interface.

Instances of this type may be created using [Marshal] with the [BER]
encoding rule constant.

See also [DERPacket], which extends from this type.
*/
type BERPacket struct {
	data   []byte
	offset int
}

/*
Type returns [BER], identifying the receiver as an ASN.1 Basic Encoding
Rules [Packet] qualifier.
*/
func (r BERPacket) Type() EncodingRule { return BER }

/*
Class returns an integer alongside an error following an attempt to parse
the outermost class identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Class() (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	return parseClassIdentifier(buf[r.Offset():])
}

/*
Tag returns an integer alongside an error following an attempt to parse
the outermost tag identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Tag() (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	tag, _, err := parseTagIdentifier(buf[r.Offset():])
	return tag, err
}

/*
Compound returns a Boolean alongside an error following an attempt to parse the
outermost compound identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Compound() (bool, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return false, errorOutOfBounds
	}
	return parseCompoundIdentifier(buf[r.Offset():])
}

/*
Bytes returns the "body" of the underlying buffer alongside an error following an attempt
to extract all but the outermost header information (omit class, tag, etc.) up to and not
including the next payload.
*/
func (r BERPacket) Bytes() ([]byte, error) {
	return parseBody(r.Data(), r.Offset(), r.Type())
}

/*
FullBytes returns a byte slice representing data[:offset].
*/
func (r BERPacket) FullBytes() ([]byte, error) {
	return parseFullBytes(r.Data(), r.Offset(), r.Type())
}

/*
Hex returns the hexadecimal encoding of the underlying encoded value
within the receiver instance.
*/
func (r BERPacket) Hex() string { return formatHex(&r) }

/*
Len returns the integer length of the underlying byte buffer within
the receiver instance.
*/
func (r BERPacket) Len() int { return len(r.data) }

/*
HasMoreData returns a Boolean value indicative of whether there are more bytes remaining
to be processed.
*/
func (r BERPacket) HasMoreData() bool { return r.offset < len(r.data) }

/*
Data returns the underlying byte slice.
*/
func (r BERPacket) Data() []byte { return r.data }

/*
Append appends data to the receiver instance.
*/
func (r *BERPacket) Append(data ...byte) {
	if r == nil || len(data) == 0 {
		return
	}
	need := len(r.data) + len(data)

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
func (r *BERPacket) Offset() int { return r.offset }

/*
SetOffset replaces the current offset position index of the underlying value within the receiver
instance with a user-supplied value.

This method is intended for use in special cases where a particular packet may need to be re-read
for some reason, or if it is necessary to write additional data.

Supplying an integer of negative one (-1) will set the offset to the final character in the
underlying buffer if non-zero in length.

If no variadic input is provided,, the offset position index is set to zero (0).
*/
func (r *BERPacket) SetOffset(offset ...int) { setPacketOffset(r, offset...) }

/*
Free frees the receiver instance.
*/
func (r *BERPacket) Free() {
	if cap(r.data) != 0 {
		buf := r.data[:0]
		bufPool.Put(&buf)
	}
	*r = BERPacket{}
	berPktPool.Put(r)
}

/*
PeekTLV returns [TLV] alongside an error. This method is similar to the standard
[Packet.TLV] method, except this method does not advance the offset.
*/
func (r *BERPacket) PeekTLV() (TLV, error) {
	sub := r.Type().New(r.Data()...)
	sub.SetOffset(r.Offset())
	return getTLV(sub, nil)
}

/*
TLV returns an instance of [TLV] alongside an error following an attempt
to read the next [BER] tag/length header.
*/
func (r *BERPacket) TLV() (TLV, error) { return getTLV(r, nil) }

/*
WriteTLV returns an int following an attempt to write a [BER] tag/length
header to the receiver buffer.
*/
func (r *BERPacket) WriteTLV(tlv TLV) error { return writeTLV(r, tlv, nil) }

/*
Packet returns an instance of [Packet] alongside an error following an attempt to read
the next L (length) bytes from the receiver instance into the return [Packet].

This method is used in cases where a constructed type, i.e.: a SEQUENCE (struct), resides
within another constructed type via nesting.

Note that successful use of this method shall advance the offset to the end of the extracted
[Packet] (position offset+length). The receiver offset is not modified.
*/
func (r *BERPacket) Packet(L int) (Packet, error) { return extractPacket(r, L) }

func readIndefiniteContents(data []byte, offset int) (contents []byte, newOffset int, err error) {
	for i := offset; i < len(data)-1; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 {
			return data[offset:i], i + 2, nil
		}
	}
	return nil, 0, mkerr("Missing end-of-contents marker")
}

func encodeBERLengthInto(dst *[]byte, n int) {
	if n == -1 { // indefinite
		*dst = append(*dst, 0x80)
		return
	}
	encodeDERLengthInto(dst, n)
}

var berPktPool = sync.Pool{New: func() any { return &BERPacket{} }}

func getBERPacket() *BERPacket { return berPktPool.Get().(*BERPacket) }
func putBERPacket(p *BERPacket) {
	*p = BERPacket{}
	berPktPool.Put(p)
}
