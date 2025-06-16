package asn1plus

/*
vts.go contains all types and methods pertaining to the ASN.1
VIDEOTEX STRING type.
*/

import (
	"unicode/utf8"
	"unsafe"
)

/*
Deprecated: VideotexString implements the ASN.1 VIDEOTEX STRING type (tag 21)
per ITU-T T-Series Recommendations [T.100] and [T.101].

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.

[T.100]: https://www.itu.int/rec/T-REC-T.100
[T.101]: https://www.itu.int/rec/T-REC-T.101
*/
type VideotexString string

/*
NewVideotexString returns an instance of [VideotexString] alongside an
error following an attempt to marshal x.
*/
func NewVideotexString(x any, constraints ...Constraint[VideotexString]) (VideotexString, error) {
	var (
		raw string
		err error
		vts VideotexString
	)

	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case VideotexString:
		raw = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 VIDEOTEX STRING")
	}

	runes := []rune(raw)
	for i := 0; i < len(runes) && err == nil; i++ {
		if char := runes[i]; !isVideotex(char) {
			err = mkerr("Invalid ASN.1 VIDEOTEX STRING character: " + itoa(int(char)))
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[VideotexString] = constraints
		err = group.Validate(VideotexString(raw))
	}

	if err == nil {
		vts = VideotexString(raw)
	}

	return vts, err
}

/*
Len returns the integer length of the receiver instance.
*/
func (r VideotexString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r VideotexString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r VideotexString) String() string { return string(r) }

/*
Tag returns the integer constant [TagVideotexString].
*/
func (r VideotexString) Tag() int { return TagVideotexString }

/*
IsPrimitive returns true, indicative the receiver is a known
ASN.1 primitive.
*/
func (r VideotexString) IsPrimitive() bool { return true }

func (r VideotexString) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		start := pkt.Offset()
		data := stringBytes(string(r))
		tag, class := effectiveTag(r.Tag(), 0, opts)
		tlv := t.newTLV(class, tag, len(data), false, data...)
		if err = writeTLV(pkt, tlv, opts); err == nil {
			n = pkt.Offset() - start
		}
	default:
		err = mkerr("Unsupported packet type for VIDEOTEX STRING")
	}
	return
}

func (r *VideotexString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}
	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(TagVideotexString, pkt, tlv, opts); err == nil {
			if pkt.Offset()+tlv.Length > pkt.Len() {
				return errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
			}

			// byte-wise rune validation – zero allocations
			for i := 0; i < len(data); {
				rn, sz := utf8.DecodeRune(data[i:])
				if rn == utf8.RuneError || !isVideotex(rn) {
					return mkerr("Invalid ASN.1 VIDEOTEX STRING character")
				}
				i += sz
			}

			// zero-copy view of the payload
			*r = VideotexString(unsafe.String(&data[0], len(data)))

			pkt.SetOffset(pkt.Offset() + tlv.Length)
		}

	}
	return
}

func isVideotex(ch rune) bool {
	if ch < 0 || ch > 0xFFFF { // we only built the BMP bitmap
		return false
	}
	word := ch >> 6
	bit := ch & 63
	return (videotexBitmap[word]>>bit)&1 != 0
}

var videotexBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			videotexBitmap[r>>6] |= 1 << (r & 63)
		}
	}

	set(0x0020, 0x007E) // ASCII (including SPACE)
	set(0x00A0, 0x00FF) // Latin‑1 Supplement
	set(0x0100, 0x017F) // Latin Extended-A
	set(0x0180, 0x024F) // Latin Extended-B
	set(0x0370, 0x03FF) // Greek
	set(0x0400, 0x04FF) // Cyrillic
	set(0x0530, 0x058F) // Armenian
	set(0x0590, 0x05FF) // Hebrew
	set(0x0600, 0x06FF) // Arabic
	set(0x2500, 0x257F) // Box drawing
	set(0x2580, 0x259F) // Blocks
	set(0x25A0, 0x25FF) // Geometric shapes
	set(0x2600, 0x26FF) // Misc symbols
	set(0x2700, 0x27BF) // Dingbats
	set(0x3000, 0x303F) // CJK symbols
	set(0x4E00, 0x9FFF) // Common CJK Unified Ideographs (for Japanese Kanji or Chinese characters)
}
