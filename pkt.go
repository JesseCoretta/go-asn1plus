package asn1plus

/*
pkt.go contains all types and methods pertaining to the payload
abstraction interface known as Packet.
*/

import "sync"

/*
Packet implements a generic ASN.1 packet of any supported codec.

Qualifying instances of this interface serve two purposes:

  - Provide an easy-to-use "Packet" abstraction for a payload
  - Serve as an equivalent to [encoding/asn1.RawValue]
*/
type Packet interface {
	// Type returns the encoding rule honored and implemented
	// by the receiver instance.
	Type() EncodingRule

	// Class returns an integer alongside an error following
	// an attempt to extract the ASN.1 class from the buffer.
	Class() (int, error)

	// Tag returns an integer alongside an error follwing an
	// attempt to extract the ASN.1 tag from the buffer.
	Tag() (int, error)

	// Compound returns a Boolean alongside an error following
	// an attempt to extract the ASN.1 compound flag from the
	// buffer.
	Compound() (bool, error)

	// Data returns the unabridged buffer contents.
	Data() []byte

	// Bytes returns a byte slice alongside an error following
	// an attempt to extract the body of the underlying buffer.
	Bytes() ([]byte, error)

	// FullBytes returns a byte slice alongside an error following
	// an attempt to extract the header and body of the underlying
	// buffer.
	FullBytes() ([]byte, error)

	// Len returns the integer length of the underlying buffer.
	Len() int

	// Hex returns the hexadecimal string representation of the
	// underlying buffer.
	Hex() string

	// Offset returns the integer "cursor" position currently set
	// within the underlying buffer.
	Offset() int

	// Packet returns an instance of Packet alongside an error
	// following an attempt to extract a "sub packet" beginning
	// at the input integer position.
	Packet(int) (Packet, error)

	// HasMoreData returns a Boolean value indicative of content
	// existing past the point of the current offset position.
	HasMoreData() bool

	// PeekTLV returns an instance of TLV alongside an error following
	// an attempt to determine the current TLV without advancing the
	// offset currently set within the underlying buffer.
	PeekTLV() (TLV, error)

	// TLV returns an instance of TLV alongside an error following an
	// attempt to determine the current TLV. When used, this method will
	// advance the current offset within the underlying buffer.
	TLV() (TLV, error)

	// WriteTLV returns an error following an attempt to write the input
	// instance of TLV to the receiver instance.
	WriteTLV(TLV) error

	// Append appends zero (0) or more bytes to the underlying buffer.
	Append(...byte)

	// SetOffset sets the underlying buffer offset to the input integer.
	SetOffset(...int)

	// Free frees the receiver instance from memory.
	Free()
}

/*
invalidPacket is the default type instance used for returns in bogus
scenarios for the purpose of panic protection when used carelessly.
*/
type invalidPacket struct{}

func (_ invalidPacket) Type() EncodingRule           { return invalidEncodingRule }
func (_ invalidPacket) Data() []byte                 { return nil }
func (_ invalidPacket) Class() (int, error)          { return -1, errorInvalidPacket }
func (_ invalidPacket) Tag() (int, error)            { return -1, errorInvalidPacket }
func (_ invalidPacket) Bytes() ([]byte, error)       { return nil, errorInvalidPacket }
func (_ invalidPacket) FullBytes() ([]byte, error)   { return nil, errorInvalidPacket }
func (_ invalidPacket) HasMoreData() bool            { return false }
func (_ invalidPacket) Compound() (bool, error)      { return false, errorInvalidPacket }
func (_ invalidPacket) Offset() int                  { return 0 }
func (_ invalidPacket) Packet(_ int) (Packet, error) { return invalidPacket{}, errorInvalidPacket }
func (_ invalidPacket) SetOffset(_ ...int)           {}
func (_ invalidPacket) Free()                        {}
func (_ invalidPacket) Hex() string                  { return `` }
func (_ invalidPacket) Len() int                     { return 0 }
func (_ invalidPacket) Append(_ ...byte)             {}
func (_ invalidPacket) PeekTLV() (TLV, error)        { return TLV{}, errorInvalidPacket }
func (_ invalidPacket) WriteTLV(_ TLV) error         { return errorInvalidPacket }
func (_ invalidPacket) TLV() (TLV, error)            { return TLV{}, errorInvalidPacket }

func extractPacket(pkt Packet, L int) (sub Packet, err error) {
	sub = invalidPacket{}

	if pkt.Offset()+L > pkt.Len() {
		err = errorASN1Expect(L, pkt.Len()-pkt.Offset(), "Length")
	} else {
		off := pkt.Offset()
		innerData := pkt.Data()[off : off+L]
		pkt.SetOffset(off + L)
		sub = pkt.Type().New(innerData...)
	}

	return sub, err
}

func setPacketOffset(pkt Packet, offset ...int) {
	var off int
	if len(offset) > 0 {
		if offset[0] == -1 && pkt.Len() > 1 {
			off = pkt.Len() - 1
		} else if offset[0] >= 0 {
			off = offset[0]
		}
	} else {
		off = 0
	}

	switch pkt.Type() {
	case BER:
		pkt.(*BERPacket).offset = off
	case CER:
		pkt.(*CERPacket).offset = off
	case DER:
		pkt.(*DERPacket).offset = off
	}
}

func formatHex(input any) string {
	var data []byte

	switch tv := input.(type) {
	case []byte:
		data = tv
	case Packet:
		data = tv.Data()
	}

	if len(data) == 0 {
		return ""
	}

	// The first byte always exists. Tags with value < 31 are encoded in one byte;
	// if the tag number equals 31, then the tag field is in multi-octet form.
	tagEnd := 1
	if data[0]&0x1F == 0x1F {
		// Multi-octet tag: continue until an octet with the MSB off is found.
		for tagEnd < len(data) && data[tagEnd]&0x80 != 0 {
			tagEnd++
		}
		// Include the final octet with MSB off.
		if tagEnd < len(data) {
			tagEnd++
		}
	}
	tagBytes := data[:tagEnd]

	if tagEnd >= len(data) {
		return trimS(uc(hexstr(data)))
	}

	var lengthEnd int
	firstLengthByte := data[tagEnd]
	// If the first length byte is 0x80 then it's indefinite length;
	// Or if it is < 0x80 it's the definite short-form length.
	if firstLengthByte == 0x80 || firstLengthByte < 0x80 {
		lengthEnd = tagEnd + 1
	} else {
		// Long form: the low 7 bits indicate the number of length octets.
		numLengthBytes := int(firstLengthByte & 0x7F)
		lengthEnd = tagEnd + 1 + numLengthBytes
		if lengthEnd > len(data) {
			lengthEnd = len(data)
		}
	}

	lengthBytes := data[tagEnd:lengthEnd]
	contentBytes := data[lengthEnd:]

	tagStr := hexstr(tagBytes)
	lengthStr := hexstr(lengthBytes)
	contentStr := hexstr(contentBytes)

	return trimS(uc(tagStr + " " + lengthStr + " " + contentStr))
}

func parseClassIdentifier(b []byte) (class int, err error) {
	class = -1
	if len(b) == 0 {
		err = errorEmptyIdentifier
	} else {
		class = int(b[0] >> 6) // bits 8–7
	}

	return
}

func parseCompoundIdentifier(b []byte) (compound bool, err error) {
	if len(b) == 0 {
		err = errorEmptyIdentifier
	} else {
		compound = b[0]&0x20 != 0 // bit 6 (P/C)
	}

	return
}

func parseTagIdentifier(b []byte) (tag int, idLen int, err error) {
	if len(b) == 0 {
		err = errorEmptyIdentifier
		return
	}

	tag = int(b[0] & 0x1F) // bits 5–1
	idLen = 1

	if tag != 0x1F {
		return // low-tag-number form – finished
	}

	// High-tag-number form – base-128 continuation
	tag = 0
	for i := 1; i < len(b); i++ {
		idLen++
		ch := b[i]
		tag = (tag << 7) | int(ch&0x7F)

		if ch&0x80 == 0 { // MSB 0 ⇒ last byte
			return
		}
		if i == 4 { // max 5 bytes = 28 bits per § 8.1 of ITU-T rec. X.690
			return 0, 0, errorTagTooLarge
		}
	}
	return 0, 0, errorTruncatedTag
}

// parseBody returns the content octets of the element that starts at `off`.
// • For DER:  indefinite-length encodings are **rejected** per X.690 §10.1.
// • For BER:  -1 length means “scan until matching EOC (00 00)”.
func parseBody(b []byte, off int, typ EncodingRule) ([]byte, error) {
	sub := b[off:]

	_, idLen, err := parseTagIdentifier(sub)
	if err != nil {
		return nil, err
	}

	length, lenLen, err := parseLength(sub[idLen:])
	if err != nil {
		return nil, err
	}

	start := off + idLen + lenLen

	if length >= 0 {
		end := start + length
		if end > len(b) {
			return nil, errorTruncatedContent
		}
		return b[start:end], nil
	}

	// BER indefinite
	if !typ.allowsIndefinite() {
		return nil, errorIndefiniteProhibited
	}
	relEnd, err := findEOC(sub[idLen+lenLen:])
	if err != nil {
		return nil, err
	}
	return b[start : start+relEnd], nil
}

func parseFullBytes(data []byte, off int, typ EncodingRule) ([]byte, error) {
	sub := data[off:]
	if len(sub) == 0 {
		sub = data
		off = 0
	}

	_, idLen, err := parseTagIdentifier(sub)
	if err != nil {
		return nil, err
	}

	length, lenLen, err := parseLength(sub[idLen:])
	if err != nil {
		return nil, err
	}

	if !typ.allowsIndefinite() && length == -1 {
		return nil, errorIndefiniteProhibited
	}

	if length >= 0 {
		end := off + idLen + lenLen + length
		if end > len(data) {
			return nil, errorTruncatedContent
		}
		return data[off:end], nil
	}

	relEnd, err := findEOC(sub[idLen+lenLen:])
	if err != nil {
		return nil, err
	}
	end := off + idLen + lenLen + relEnd + 2
	if end > len(data) {
		return nil, errorTruncatedContent
	}
	return data[off:end], nil
}

// findEOC walks a BER indefinite-length body and returns the index where the
// *two-byte* EOC (0x00 0x00) that closes the **outermost** container begins.
func findEOC(b []byte) (int, error) {
	depth := 0
	i := 0
	for i < len(b) {
		// Reached EOC for current depth?
		if b[i] == 0x00 && i+1 < len(b) && b[i+1] == 0x00 {
			if depth == 0 {
				return i, nil
			}
			depth--
			i += 2
			continue
		}

		// Otherwise parse the child TLV header to know how far to jump.
		_, idLen, err := parseTagIdentifier(b[i:])
		if err != nil {
			return 0, err
		}
		l, lenLen, err := parseLength(b[i+idLen:])
		if err != nil {
			return 0, err
		}

		i += idLen + lenLen
		if l == -1 { // nested indefinite
			depth++
		} else {
			i += l // skip over definite body
		}
	}
	return 0, errorTruncatedContent
}

// parseLength parses the length octet(s) that follow an identifier.
// It returns
//   - length  –  the content-octet count;
//     ‑1 means “indefinite length” (per BER).
//   - lenLen  –  number of bytes that expressed the length.
//   - err     –  non-nil on malformed encodings.
//
// The routine itself applies *no* DER-specific legality checks; callers
// decide what to do with –1 (indefinite) or with non-minimal long forms.
// This keeps it reusable for both BER and DER.
//
// b must start at the first length octet.
func parseLength(b []byte) (length int, lenLen int, err error) {
	if len(b) == 0 {
		return 0, 0, errorEmptyLength
	}

	first := b[0]
	lenLen = 1

	// Short-form  (bit 8 = 0)
	if first&0x80 == 0 {
		length = int(first)
		return
	}

	// Long- or indefinite-form  (bit 8 = 1)
	n := int(first & 0x7F) // lower 7 bits = # of subsequent octets

	if n == 0 {
		length = -1
		return
	}

	// Reject pathological encodings early
	if n > 4 { // 32-bit length cap keeps arithmetic safe
		return 0, 0, errorLengthTooLarge
	}
	if n > len(b)-1 {
		return 0, 0, errorTruncatedLength
	}

	// Assemble big-endian integer
	length = 0
	for i := 1; i <= n; i++ {
		length = (length << 8) | int(b[i])
	}
	lenLen += n
	return
}

func getPacketClass(r Packet) (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	return parseClassIdentifier(buf[r.Offset():])
}

func getPacketTag(r Packet) (int, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return 0, errorOutOfBounds
	}
	tag, _, err := parseTagIdentifier(buf[r.Offset():])
	return tag, err
}

func getPacketCompound(r Packet) (bool, error) {
	buf := r.Data()
	if r.Offset() >= len(buf) {
		return false, errorOutOfBounds
	}
	return parseCompoundIdentifier(buf[r.Offset():])
}

/*
bufPool implements a sync.Pool for efficient
slice operations.
*/
var bufPool = sync.Pool{
	New: func() any { return new([]byte) },
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(p *[]byte) { *p = (*p)[:0]; bufPool.Put(p) }

var packetConstructors map[EncodingRule]func(...byte) Packet

// This is mainly for maintainer convenience in the midst
// of implementing new encoding rules.
func panicOnMissingEncodingRuleConstructor(table map[EncodingRule]func(...byte) Packet) {
	for i := 0; i < len(encodingRules); i++ {
		rule := encodingRules[i]
		if _, found := table[rule]; !found {
			panic(mkerrf("EncodingRule ", rule.String(), " has no registered constructor"))
		}
	}
}

func init() {
	packetConstructors = map[EncodingRule]func(...byte) Packet{
		BER: newBERPacket,
		CER: newCERPacket,
		DER: newDERPacket,
	}
	panicOnMissingEncodingRuleConstructor(packetConstructors)
}
