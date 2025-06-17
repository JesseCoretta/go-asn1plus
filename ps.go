package asn1plus

/*
ps.go contains all types and methods pertaining to the ASN.1
PRINTABLE STRING type.
*/

/*
PrintableString implements [§ 41.4 of ITU-T Rec. X.680] (tag 19):

	Latin capital letters   A, B, ... Z
	Latin small letters     a, b, ... z
	Digits                  0, 1, ... 9
	SPACE
	APOSTROPHE              '
	LEFT PARENTHESIS        (
	RIGHT PARENTHESIS       )
	PLUS SIGN               +
	COMMA                   ,
	HYPHEN-MINUS            -
	FULL STOP               .
	SOLIDUS                 /
	COLON                   :
	EQUALS SIGN             =
	QUESTION MARK           ?

[§ 41.4 of ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type PrintableString string

/*
Tag returns the integer constant [TagPrintableString].
*/
func (r PrintableString) Tag() int { return TagPrintableString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r PrintableString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r PrintableString) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r PrintableString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PrintableString) IsZero() bool { return len(r) == 0 }

/*
NewPrintableString returns an instance of [PrintableString] alongside
an error following an attempt to marshal x.
*/
func NewPrintableString(x any, constraints ...Constraint[PrintableString]) (ps PrintableString, err error) {
	var raw string

	switch tv := x.(type) {
	case PrintableString:
		raw = tv.String()
	case string:
		if len(tv) == 0 {
			err = mkerr("Printable String is zero length")
			return
		}
		raw = tv
	case []byte:
		raw = string(tv)
	default:
		err = mkerr("Invalid type for ASN.1 PRINTABLE STRING")
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !isPrintableStringChar(char) {
			err = mkerrf("Invalid printable string character: ", string(char))
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[PrintableString] = constraints
		err = group.Validate(PrintableString(raw))
	}

	if err == nil {
		ps = PrintableString(raw)
	}

	return
}

func (r *PrintableString) read(pkt Packet, tlv TLV, opts *Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			var lt int = tlv.Length
			if pkt.Offset()+lt > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+lt, pkt.Len(), "Length")
			} else {
				*r = PrintableString(data)
				pkt.SetOffset(pkt.Offset() + lt)
			}
		}
	}

	return
}

func (r PrintableString) write(pkt Packet, opts *Options) (n int, err error) {
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

func isPrintableStringChar(ch rune) bool {
	if ch < 0 || ch > 0xFFFF {
		return false
	}
	word := ch >> 6
	bit := ch & 63
	return (printableStringBitmap[word]>>bit)&1 != 0
}

var printableStringBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			printableStringBitmap[r>>6] |= 1 << (r & 63)
		}
	}
	set(0x0020, 0x0020)
	set(0x0027, 0x0029)
	set(0x002B, 0x002F)
	set(0x003A, 0x003A)
	set(0x003F, 0x003F)
	set(0x0030, 0x0039)
	set(0x0041, 0x005A)
	set(0x0061, 0x007A)
}
