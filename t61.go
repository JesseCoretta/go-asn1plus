package asn1plus

/*
t61.go contains all types and methods pertaining to the ASN.1
T61 STRING (also known as a teletex string).
*/

/*
Deprecated: T61String implements the [ITU-T Rec. T.61] string (tag 20).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems. Use [UniversalString], [BMPString]
or [UTF8String].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
type T61String string

/*
Tag returns the integer constant [TagT61String].
*/
func (r T61String) Tag() int { return TagT61String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r T61String) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r T61String) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r T61String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r T61String) IsZero() bool { return len(r) == 0 }

/*
T61String returns an instance of [T61String] alongside an error
following an analysis of x in the context of a Teletex String, per
[ITU-T Rec. T.61].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
func NewT61String(x any, constraints ...Constraint[T61String]) (T61String, error) {
	var (
		raw string
		t61 T61String
		err error
	)

	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = mkerr("ASN.1 T.61 STRING is zero length")
			return t61, err
		}
		raw = tv
	case []byte:
		raw = string(tv)
	case T61String:
		raw = tv.String()
	default:
		err = mkerr("Invalid ASN.1 T.61 STRING type")
		return t61, err
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !isT61Char(char) {
			err = mkerr("Incompatible character for ASN.1 T.61 STRING: " + string(char))
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[T61String] = constraints
		err = group.Validate(T61String(raw))
	}

	if err == nil {
		t61 = T61String(raw)
	}

	return t61, err
}

func (r T61String) write(pkt Packet, opts Options) (n int, err error) {
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

func (r *T61String) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			if pkt.Offset()+tlv.Length > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
			} else {
				*r = T61String(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}

func isT61Char(ch rune) bool {
	if ch < 0 || ch > 0xFFFF {
		return false
	}
	word := ch >> 6
	bit := ch & 63
	return (t61Bitmap[word]>>bit)&1 != 0
}

var t61Bitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			t61Bitmap[r>>6] |= 1 << (r & 63)
		}
	}
	set(0x0009, 0x000f)
	set(0x0020, 0x0039)
	set(0x0041, 0x005B)
	set(0x0061, 0x007A)
	set(0x00A0, 0x00FF)
	set(0x008B, 0x008C)
	set(0x0126, 0x0127)
	set(0x0131, 0x0132)
	set(0x0140, 0x0142)
	set(0x0149, 0x014A)
	set(0x0152, 0x0153)
	set(0x0166, 0x0167)
	set(0x0300, 0x0304)
	set(0x0306, 0x0308)
	set(0x030A, 0x030C)
	set(0x0327, 0x0328)
	set(0x009B, 0x009B)
	set(0x005C, 0x005C)
	set(0x005D, 0x005D)
	set(0x005F, 0x005F)
	set(0x003F, 0x003F)
	set(0x007C, 0x007C)
	set(0x007F, 0x007F)
	set(0x001D, 0x001D)
	set(0x0111, 0x0111)
	set(0x0138, 0x0138)
	set(0x0332, 0x0332)
	set(0x2126, 0x2126)
	set(0x013F, 0x013F)
	set(0x014B, 0x014B)
}
