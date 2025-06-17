package asn1plus

/*
gen.go contains all types and methods pertaining to the ASN.1
GENERAL STRING type.
*/

/*
Deprecated: GeneralString implements the ASN.1 GENERAL STRING type (tag 27).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type GeneralString string

/*
NewGeneralString returns an instance of [GeneralString] alongside an error
following attempt to marshal x.
*/
func NewGeneralString(x any, constraints ...Constraint[GeneralString]) (gen GeneralString, err error) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case GeneralString:
		s = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 GRAPHIC STRING")
		return
	}

	_, err = scanGeneralStringChars(s)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[GeneralString] = constraints
		err = group.Validate(GeneralString(s))
	}

	if err == nil {
		gen = GeneralString(s)
	}

	return
}

func scanGeneralStringChars(x string) (gs string, err error) {
	for _, ch := range x {
		if !isGeneralStringChar(ch) {
			err = mkerrf("Invalid character for ASN.1 GENERAL STRING: ", string(ch))
		}
	}

	if err == nil {
		gs = x
	}

	return
}

/*
Len returns the integer byte length of the receiver instance.
*/
func (r GeneralString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r GeneralString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralString) String() string { return string(r) }

/*
Tag returns the ASN.1 tag for GeneralString.
*/
func (r GeneralString) Tag() int { return TagGeneralString }

/*
IsPrimitive returns true, indicating that the receiver instance is
a known ASN.1 primitive.
*/
func (r GeneralString) IsPrimitive() bool { return true }

func (r GeneralString) write(pkt Packet, opts *Options) (n int, err error) {
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

func (r *GeneralString) read(pkt Packet, tlv TLV, opts *Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}
	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	}
	return
}

func (r *GeneralString) readBER(pkt Packet, tlv TLV, opts *Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		var gen string
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else if gen, err = scanGeneralStringChars(string(data)); err == nil {
			*r = GeneralString(gen)
			pkt.SetOffset(pkt.Offset() + tlv.Length)
		}
	}

	return
}

func isGeneralStringChar(ch rune) bool {
	if ch < 0 || ch > 0x00FF {
		return false
	}
	word := ch >> 6
	bit := ch & 63
	return (generalStringBitmap[word]>>bit)&1 != 0
}

var generalStringBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			generalStringBitmap[r>>6] |= 1 << (r & 63)
		}
	}
	set(0x0000, 0x007F) // Basic Latin (includes control characters)
	set(0x0080, 0x009F) // C1 Controls (rarely printable but part of the charset)
	set(0x00A0, 0x00FF) // Latin‑1 Supplement (graphical characters)
}
