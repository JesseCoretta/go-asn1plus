//go:build !asn1_no_der

package asn1plus

/*
der.go contains DER-focused components. See also ber.go.
*/

import "io"

/*
DERPacket encapsulates an [ITU-T Rec. X.690] DER-encoded byte
slice and an offset. It extends from [BERPacket].

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
type DERPacket BERPacket

/*
Type returns [DER], identifying the receiver as an ASN.1 Distinguished Encoding
Rules [PDU] qualifier.
*/
func (r DERPacket) Type() EncodingRule { return DER }

/*
ID returns the unique string identifier associated with the receiver instance.

Note that if this package is not compiled or run with "-tags asn1debug", this
method will always return a zero string.
*/
func (r DERPacket) ID() string { return r.id }

/*
Class returns an integer alongside an error following an attempt to parse
the outermost class identifier present within the underlying receiver buffer.
*/
func (r DERPacket) Class() (int, error) { return getPacketClass(&r) }

/*
Tag returns an integer alongside an error following an attempt to parse
the outermost tag identifier present within the underlying receiver buffer.
*/
func (r DERPacket) Tag() (int, error) { return getPacketTag(&r) }

/*
Compound returns a Boolean alongside an error following an attempt to parse the
outermost compound identifier present within the underlying receiver buffer.
*/
func (r DERPacket) Compound() (bool, error) { return getPacketCompound(&r) }

/*
Bytes returns the "body" of the underlying buffer alongside an error following an attempt
to extract all but the outermost header information (omit class, tag, etc.) up to and not
including the next payload.
*/
func (r DERPacket) Bytes() ([]byte, error) {
	return parseBody(r.Data(), r.Offset(), r.Type())
}

/*
FullBytes returns a byte slice representing data[:offset].
*/
func (r DERPacket) FullBytes() ([]byte, error) {
	return parseFullBytes(r.Data(), r.Offset(), r.Type())
}

/*
Hex returns the hexadecimal encoding of the underlying encoded value
within the receiver instance.
*/
func (r DERPacket) Hex() string { return formatHex(&r) }

/*
Dump returns an error following an attempt to write the receiver
instance into w.

The variadic wrapAt value defines the maximum number of characters
displayed per line before the value is wrapped. The default is 24,
and can be configured no less than 16.
*/
func (r *DERPacket) Dump(w io.Writer, wrapAt ...int) error { return dumpPacket(r, w) }

/*
Len returns the integer length of the underlying byte buffer within
the receiver instance.
*/
func (r DERPacket) Len() int { return len(r.data) }

/*
HasMoreData returns a Boolean value indicative of whether there are more bytes remaining
to be processed.
*/
func (r DERPacket) HasMoreData() bool { return r.offset < r.Len() }

/*
Data returns the underlying byte slice.
*/
func (r *DERPacket) Data() []byte { return r.data }

/*
Append appends data to the receiver instance.
*/
func (r *DERPacket) Append(data ...byte) { (*BERPacket)(r).Append(data...) }

/*
Offset returns the current offset position index of the underlying value within the receiver
instance.
*/
func (r *DERPacket) Offset() int { return r.offset }

/*
SetOffset replaces the current offset position index of the underlying value within the receiver
instance with a user-supplied value.

This method is intended for use in special cases where a particular packet may need to be re-read
for some reason.

Supplying an integer of negative one (-1) will set the offset to the final character in the
underlying buffer if non-zero in length.

If no variadic input is provided,, the offset position index is set to zero (0).
*/
func (r *DERPacket) SetOffset(offset ...int) { r.offset = setPacketOffset(r, offset...) }

/*
Free frees the receiver instance.
*/
func (r *DERPacket) Free() { (*BERPacket)(r).Free() }

/*
PeekTLV returns [TLV] alongside an error. This method is similar to the standard
[PDU.TLV] method, except this method does not advance the offset.
*/
func (r *DERPacket) PeekTLV() (TLV, error) { return (*BERPacket)(r).PeekTLV() }

/*
TLV returns an instance of [TLV] alongside an error following an attempt
to read the next [DER] tag/length header.
*/
func (r *DERPacket) TLV() (TLV, error) { return getTLV(r, nil) }

/*
WriteTLV returns an int following an attempt to write a [DER] tag/length
header to the receiver buffer.
*/
func (r *DERPacket) WriteTLV(tlv TLV) error { return writeTLV(r, tlv, nil) }

func newDERPacket(src ...byte) PDU {
	r := newBERPacket(src...)
	bp, _ := r.(*BERPacket)
	return (*DERPacket)(bp)
}

func init() {
	activeEncodingRules |= DER
	pDUConstructors[DER] = newDERPacket
}
