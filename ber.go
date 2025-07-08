package asn1plus

/*
ber.go contains BER-focused components. See also der.go.
*/

import (
	"io"
	"sync"
)

/*
BERPacket implements a data encapsulation and transport type to store
[ITU-T Rec. X.690] [BER]-encoded content. It qualifies the [PDU]
interface.

Instances of this type may be created using [Marshal] with the [BER]
encoding rule constant.

See also [CERPacket] and [DERPacket], both of which extend from this
type.

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
type BERPacket struct {
	id     string
	data   []byte
	offset int
}

/*
Type returns [BER], identifying the receiver as an ASN.1 Basic Encoding
Rules [PDU] qualifier.
*/
func (r BERPacket) Type() EncodingRule { return BER }

/*
ID returns the unique string identifier associated with the receiver instance.

Note that if this package is not compiled or run with "-tags asn1debug", this
method will always return a zero string.
*/
func (r BERPacket) ID() string { return r.id }

/*
Class returns an integer alongside an error following an attempt to parse
the outermost class identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Class() (int, error) { return getPacketClass(&r) }

/*
Tag returns an integer alongside an error following an attempt to parse
the outermost tag identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Tag() (int, error) { return getPacketTag(&r) }

/*
Compound returns a Boolean alongside an error following an attempt to parse the
outermost compound identifier present within the underlying receiver buffer.
*/
func (r BERPacket) Compound() (bool, error) { return getPacketCompound(&r) }

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
Dump returns an error following an attempt to write the receiver
instance into w.

The variadic wrapAt value defines the maximum number of characters
displayed per line before the value is wrapped. The default is 24,
and can be configured no less than 16.
*/
func (r *BERPacket) Dump(w io.Writer, wrapAt ...int) error { return dumpPacket(r, w) }

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
	id := newLItem(r.id, r.Type(), "PDU")
	debugEnter(data)
	defer func() { debugExit() }()

	if r == nil || len(data) == 0 {
		return
	}
	need := r.Len() + len(data)

	if c := cap(r.data); c < need {
		debugTrace(id, newLItem(need, "need"), newLItem(c, "cap"))

		bufPtr := bufPool.Get().(*[]byte)
		if cap(*bufPtr) < need {
			n2 := need * 2
			debugTrace(id, newLItem(n2, "alloc new cap"))
			*bufPtr = make([]byte, 0, n2)
		}
		newBuf := append((*bufPtr)[:0], r.data...)

		if cap(r.data) != 0 {
			old := r.data[:0]
			bufPool.Put(&old)
		}
		r.data = newBuf
		debugEvent(EventTrace|EventPDU,
			id, newLItem(r.data, "after growth"))
	}

	r.data = append(r.data, data...)
	debugEvent(EventTrace|EventPDU,
		id, newLItem(r.data, "after append"))
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

If no variadic input is provided, the offset position index is set to zero (0).
*/
func (r *BERPacket) SetOffset(offset ...int) { r.offset = setPacketOffset(r, offset...) }

/*
Free frees the receiver instance.
*/
func (r *BERPacket) Free() {
	debugEnter(r)
	defer func() { debugExit() }()

	if c := cap(r.data); c != 0 {
		debugEvent(EventTrace|EventPDU,
			r, newLItem(c, "release cap"))
		buf := r.data[:0]
		bufPool.Put(&buf)
	}

	lb := r.Len()
	*r = BERPacket{}
	debugEvent(EventTrace|EventPDU,
		r, newLItem([]int{lb, r.Len()}, "free b/a len"))

	bcdPktPool.Put(r)
}

/*
PeekTLV returns [TLV] alongside an error. This method is similar to the standard
[PDU.TLV] method, except this method does not advance the offset.
*/
func (r *BERPacket) PeekTLV() (TLV, error) {
	var tlv TLV
	var err error
	debugEnter(r)
	defer func() { debugExit(tlv, newLItem(err)) }()

	sub := r.Type().New(r.Data()...)
	sub.(*BERPacket).id = r.id
	sub.SetOffset(r.Offset())
	tlv, err = getTLV(sub, nil)
	return tlv, err
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

func newBERPacket(src ...byte) (pkt PDU) {
	debugEnter(src)
	defer func() { debugExit(pkt) }()

	b := bcdPktPool.Get().(*BERPacket)
	b.id = makePacketID()
	debugTrace(b.id, "New"+b.Type().String()+"PDU")

	cl, sl := cap(b.data), len(src)
	debugTrace(newLItem(b, "from pool"), newLItem([]int{cl, sl}, "cap/len"))

	if cl < sl {
		debugTrace(b, newLItem([]int{sl, cl}, "have/need cap"))
		bufPtr := bufPool.Get().(*[]byte)
		if cap(*bufPtr) < sl {
			newCap := roundup(sl)
			debugTrace(b, newLItem(newCap, "alloc buf (new cap)"))
			*bufPtr = make([]byte, 0, newCap)
		}
		b.data = *bufPtr
		cl = cap(b.data)
		debugTrace(b, newLItem(cl, "new buf cap"))
	}
	b.data = append(b.data[:0], src...)
	debugTrace(b, newLItem(b.data, "load"), newLItem(len(b.data), "len"))
	pkt = b
	return
}

/*
Deprecated: Packet returns an instance of [PDU] alongside an error following an
attempt to read the next L (length) bytes from the receiver instance into the
return [PDU].

This method is used in cases where a constructed type, i.e.: a SEQUENCE (struct),
resides within another constructed type via nesting.

Note that successful use of this method shall advance the offset to the end of the
extracted [PDU] (position offset+length). The receiver offset is not modified.
*/
func (r *BERPacket) Packet(L int) (PDU, error) { return extractPacket(r, L) }

/*
// TODO: reinvestigate this
//
func readIndefiniteContents(r PDU, d []byte) ([]byte, int, error) {
	off := r.Offset()
	var val []byte
	var err error
	for err == nil {
		if off+2 <= len(d) && d[off] == 0x00 && d[off+1] == 0x00 {
			off += 2
			break
		}
		var t TLV
		if t, err = getTLV(r, nil); err == nil {
			val = append(val, t.Value...)
			off = r.Offset()
		}
	}
	return val, off, err
}
*/

func encodeBERLengthInto(dst *[]byte, n int) {
	if n == -1 { // indefinite
		*dst = append(*dst, 0x80)
		debugCodec(newLItem(*dst, BER, "INDEFINITE-LENGTH"))
		return
	}
	encodeBCDLengthInto(dst, n)
}

func encodeBCDLengthInto(dst *[]byte, n int) {
	debugEnter(newLItem(n, "n"))
	defer func() { debugExit() }()

	defer debugPath(*dst, newLItem(n, "len"))()

	if n < 128 { // short form
		*dst = append(*dst, byte(n))
		debugCodec(newLItem(n, "short form"))
		return
	}
	debugCodec(newLItem(n, "long form"))

	// long form – emit the *minimal* number of octets
	var tmp [8]byte // handles 64-bit length
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	byteCount := len(tmp) - i
	debugCodec(newLItem(byteCount, "octets"))

	*dst = append(*dst, 0x80|byte(len(tmp)-i))
	*dst = append(*dst, tmp[i:]...)

	debugCodec(newLItem(tmp[i:byteCount+i], "encoded length"))
}

var bcdPktPool = sync.Pool{New: func() any { return &BERPacket{} }}

func init() {
	activeEncodingRules |= BER
	pDUConstructors[BER] = newBERPacket
}
