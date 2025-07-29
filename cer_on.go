//go:build !asn1_no_cer

package asn1plus

/*
cer.go contains CER-focused components. See also ber.go and der.go.
*/

import "io"

/*
CERPacket encapsulates an [ITU-T Rec. X.690] CER-encoded byte
slice and an offset. It extends from [BERPacket].

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
type CERPacket BERPacket

/*
Type returns [CER], identifying the receiver as an ASN.1 Distinguished Encoding
Rules [PDU] qualifier.
*/
func (r CERPacket) Type() EncodingRule { return CER }

/*
ID returns the unique string identifier associated with the receiver instance.

Note that if this package is not compiled or run with "-tags asn1_debug", this
method will always return a zero string.
*/
func (r CERPacket) ID() string { return r.id }

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
	return parseBody(r.Data(), r.Offset(), CER)
}

/*
FullBytes returns a byte slice representing data[:offset].
*/
func (r CERPacket) FullBytes() ([]byte, error) {
	return parseFullBytes(r.Data(), r.Offset(), CER)
}

/*
Hex returns the hexadecimal encoding of the underlying encoded value
within the receiver instance.
*/
func (r CERPacket) Hex() string { return formatHex(&r) }

/*
Dump returns an error following an attempt to write the receiver
instance into w.

The variadic wrapAt value defines the maximum number of characters
displayed per line before the value is wrapped. The default is 24,
and can be configured no less than 16.
*/
func (r *CERPacket) Dump(w io.Writer, wrapAt ...int) error { return dumpPacket(r, w) }

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
func (r *CERPacket) Append(data ...byte) { (*BERPacket)(r).Append(data...) }

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
func (r *CERPacket) SetOffset(offset ...int) { r.offset = setPacketOffset(r, offset...) }

/*
AddOffset increments or decrements the current offset according to n. Though negative input is
permitted, the product of offset + n must not be negative itself, nor may it exceed the receiver's
buffer length.
*/
func (r *CERPacket) AddOffset(n int) { r.offset = incPacketOffset(r, n) }

/*
Free frees the receiver instance.
*/
func (r *CERPacket) Free() { (*BERPacket)(r).Free() }

/*
PeekTLV returns [TLV] alongside an error. This method is similar to the standard
[PDU.TLV] method, except this method does not advance the offset.
*/
func (r *CERPacket) PeekTLV() (TLV, error) { return (*BERPacket)(r).PeekTLV() }

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

func decodeCERLength(data []byte, offset int) (length int, bytesRead int, err error) {
	debugEnter(data, newLItem(offset, "off"))
	defer func() {
		debugExit(
			newLItem(length, "length"),
			newLItem(bytesRead, "read"),
			newLItem(err))
	}()

	if nlb := offset >= len(data); nlb {
		err = codecErrorf("CER length decode: offset>=len(data), no length byte available")
		return 0, 0, err
	}

	first := data[offset]
	debugCodec(newLItem(fmtUint(uint64(first), 2), "first byte"))
	offset++
	bytesRead = 1
	if first&indefByte == 0 {
		// Short form: one byte length.
		debugCodec(newLItem(length, "short form result"))
		return int(first), bytesRead, nil
	}

	// Long form: the lower 7 bits tell us how many octets follow.
	numOctets := int(first & shortByte)
	debugCodec(numOctets, "long form octets")
	if offset+numOctets > len(data) {
		err = codecErrorf("insufficient length bytes: need ", itoa(numOctets))
		debugCodec(newLItem(err))
		return 0, 0, err
	}

	length = 0
	for i := 0; i < numOctets; i++ {
		length = (length << 8) | int(data[offset+i])
		debugCodec(newLItem(data[offset+i], "octet["+itoa(i)+"]"))
	}

	bytesRead += numOctets
	debugCodec(newLItem([]int{length, bytesRead}, "decoded len/bytes read"))

	return length, bytesRead, nil
}

func newCERPacket(src ...byte) PDU {
	r := newBERPacket(src...)
	bp, _ := r.(*BERPacket)
	return (*CERPacket)(bp)
}

func cerSegmentedBitStringReadLoop(sub PDU) (lastUnused byte, full []byte, err error) {
	for sub.HasMoreData() {
		var seg TLV
		if seg, err = sub.TLV(); err == nil {
			if seg.Class == ClassUniversal && seg.Tag == 0 && seg.Length == 0 {
				break
			}

			if len(seg.Value) == 0 {
				err = primitiveErrorf("BIT STRING: inner segment too short")
				return
			}
			lastUnused = seg.Value[0]
			full = append(full, seg.Value[1:]...)
			sub.SetOffset(sub.Offset() + seg.Length)
		}
	}

	return
}

func cerSegmentedBitStringRead[T any](
	c *bitStringCodec[T],
	pkt PDU,
	outer TLV,
	opts *Options,
) (err error) {
	if outer.Class != ClassUniversal ||
		outer.Tag != TagBitString ||
		!outer.Compound ||
		outer.Length != -1 {
		return primitiveErrorf("BIT STRING: cerSegmentedBitStringRead: not CER indefinite")
	}

	sub := CER.New(outer.Value...)
	sub.SetOffset(0)

	var lastUnused byte
	var full []byte
	if lastUnused, full, err = cerSegmentedBitStringReadLoop(sub); err != nil {
		return
	}

	bitLength := len(full)*8 - int(lastUnused)

	for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
		err = c.decodeVerify[i](full)
	}

	if err == nil {
		var out T
		if c.decodeHook != nil {
			out, err = c.decodeHook(append([]byte{lastUnused}, full...))
		} else {
			out = fromBitString[T](BitString{
				Bytes:     append([]byte(nil), full...),
				BitLength: bitLength,
			})
		}

		if err == nil {
			cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
			if err = cc(out); err == nil {
				c.val = out
			}
		}
	}

	return err
}

func cerSegmentedBitStringWrite[T any](
	c *bitStringCodec[T],
	pkt PDU,
	opts *Options,
) (n int, err error) {
	const maxSegData = 1000

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		bs := toBitString(c.val)
		data := bs.Bytes
		total := len(data)
		remBits := bs.BitLength % 8
		overallUnused := 0
		if remBits != 0 {
			overallUnused = 8 - remBits
		}

		hdr := []byte{byte(TagBitString) | cmpndByte, indefByte}
		pkt.Append(hdr...)
		n += len(hdr)

		for off := 0; off < total; off += maxSegData {
			end := off + maxSegData
			if end > total {
				end = total
			}
			segUnused := 0
			if end == total {
				segUnused = overallUnused
			}

			val := make([]byte, 1+(end-off))
			val[0] = byte(segUnused)
			copy(val[1:], data[off:end])

			prim := CER.newTLV(
				ClassUniversal, TagBitString,
				len(val), false,
				val...,
			)
			enc := encodeTLV(prim, nil)
			pkt.Append(enc...)
			n += len(enc)
		}

		pkt.Append(indefEoC...)
		n += 2
	}

	return n, nil
}

func cerSegmentedOctetStringWrite[T TextLike](
	c *textCodec[T],
	pkt PDU,
	opts *Options,
) (written int, err error) {
	const maxSegSize = 1000

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			wire = []byte(c.val)
		}
		if err != nil {
			return 0, err
		}

		// outer header: OCTET STRING|constructed, indefinite
		hdr := []byte{byte(TagOctetString) | cmpndByte, indefByte}
		pkt.Append(hdr...)
		written += len(hdr)

		// break into 1000‐byte primitive‐OCTET‐STRING TLVs
		for off := 0; off < len(wire); off += maxSegSize {
			end := off + maxSegSize
			if end > len(wire) {
				end = len(wire)
			}
			prim := CER.newTLV(
				ClassUniversal,
				TagOctetString,
				end-off, false,
				wire[off:end]...,
			)
			enc := encodeTLV(prim, nil)
			pkt.Append(enc...)
			written += len(enc)
		}

		// EOC
		pkt.Append(indefEoC...)
		written += 2
	}

	return written, nil
}

func cerOctetStringReadBadTLV(outer TLV) (err error) {
	if outer.Class != ClassUniversal ||
		outer.Tag != TagOctetString ||
		!outer.Compound ||
		outer.Length != -1 {
		err = primitiveErrorf("OCTET STRING: cerSegmentedOctetStringRead: not CER indefinite")
	}

	return
}

func cerSegmentedOctetStringRead[T TextLike](
	c *textCodec[T],
	pkt PDU,
	outer TLV,
	opts *Options,
) (err error) {
	// validate the outer TLV
	if err = cerOctetStringReadBadTLV(outer); err != nil {
		return
	}

	sub := CER.New(outer.Value...)
	sub.SetOffset(0)

	var full []byte
	for sub.HasMoreData() && err == nil {
		var seg TLV
		if seg, err = sub.TLV(); err == nil {
			if seg.Class == ClassUniversal && seg.Tag == 0 && seg.Length == 0 {
				break
			}

			full = append(full, seg.Value...)
			sub.SetOffset(sub.Offset() + seg.Length)
		}
	}

	if err == nil {
		for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
			err = c.decodeVerify[i](full)
		}

		if err == nil {
			var val T
			if c.decodeHook != nil {
				val, err = c.decodeHook(full)
			} else {
				// copy to avoid aliasing original slice
				val = T(append([]byte(nil), full...))
			}
			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(val); err == nil {
					c.val = val
				}
			}
		}
	}

	return
}

/*
// NOT NEEDED FOR NOW.
func cerCheckEOC(offset int, data []byte) (ok bool) {
	return offset+2 <= len(data) && data[offset] == 0x00 && data[offset+1] == 0x00
}
*/

func init() {
	activeEncodingRules |= CER
	pDUConstructors[CER] = newCERPacket
}
