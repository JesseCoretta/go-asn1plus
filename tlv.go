package asn1plus

/*
tlv.go contains all types, methods and functions for the
Type-Length-Value type.
*/

func tlvString(tlv TLV) (str string) {
	str = "{invalid TLV}"
	var value []string
	data := tlv.Value
	for i := 0; i < len(data); i++ {
		value = append(value, itoa(int(data[i])))
	}

	switch tlv.Type() {
	case BER, CER, DER:
		str = "{Type: " + tlv.typ.String() +
			", Class:" + itoa(tlv.Class) +
			", Tag:" + itoa(tlv.Tag) +
			", Compound:" + bool2str(tlv.Compound) +
			", Length:" + itoa(tlv.Length) +
			", Value:[" + join(value, ` `) + "]}"
	}

	return
}

func tlvEqual(a, b TLV, length ...bool) (match bool) {
	var lenOK bool = true // assume true by default

	if len(length) > 0 && length[0] {
		lenOK = a.Length == b.Length
	}

	match = a.typ == b.typ &&
		a.Compound == b.Compound &&
		a.Class == b.Class &&
		a.Tag == b.Tag && lenOK

	return
}

/*
TLV stores discrete Type-Length-Value components. Instances of this
type are produced through the use of any [Packet] instance's "TLV()"
and "PeekTLV()" methods.

An instance of TLV knows what [EncodingRule] it implements (see the
[TLV.Type] method).
*/
type TLV struct {
	Class    int
	Tag      int
	Compound bool
	Length   int
	Value    []byte
	typ      EncodingRule
}

func (r TLV) String() string { return tlvString(r) }

/*
Type returns an instance of [EncodingRule], thereby revealing which
encoding rule is implemented.
*/
func (r TLV) Type() EncodingRule { return r.typ }

/*
Eq returns a Boolean value indicative of a match between the receiver and
input [TLV] instances. The respective lengths of the [TLV] instances will
only be evaluated if the variadic input "length" value is true.
*/
func (r TLV) Eq(tlv TLV, length ...bool) bool {
	return tlvEqual(r, tlv, length...)
}

func encodeTLV(t TLV, opts *Options) []byte {
	bufPtr := getBuf()
	b := *bufPtr

	classVal := t.Class // class bits from the TLV
	tagVal := t.Tag     // tag from the TLV
	compound := t.Compound

	if opts != nil {
		classVal = opts.Class()
		if opts.HasTag() {
			tagVal = opts.Tag()
		}
		if opts.Explicit {
			compound = true
		}
	}

	// TODO: is panic the most appropriate action?
	if tagVal < 0 {
		panic("encodeTLV: negative tag reached encoder")
	}

	var id byte = byte(classVal << 6)
	if compound {
		id |= 0x20
	}

	if tagVal < 31 {
		id |= byte(tagVal)
		b = append(b, id)
	} else {
		id |= 0x1F
		b = append(b, id)
		b = append(b, encodeBase128Int(tagVal)...)
	}

	indef := t.Type().allowsIndefinite() &&
		((opts != nil && opts.Indefinite) || t.Length < 0)

	if indef {
		b = append(b, 0x80) // indefinite-length indicator
	} else {
		encodeLengthInto(t.Type(), &b, t.Length)
	}

	b = append(b, t.Value...)

	out := append([]byte(nil), b...)
	putBuf(bufPtr)
	return out
}

func getTLV(r Packet, opts *Options) (TLV, error) {

	if r.Offset() >= r.Len() {
		return TLV{}, mkerrf(r.Type().String(), " Packet.TLV: no data available at offset ",
			itoa(r.Offset()), " (len:", itoa(r.Len()), ")")
	}

	d := r.Data()

	sub := d[r.Offset():]

	// Parse class.
	class, err := parseClassIdentifier(sub)
	if err != nil {
		return TLV{}, err
	}

	// Parse compound flag.
	compound, _ := parseCompoundIdentifier(sub)

	// Parse tag.
	tag, idLen, err := parseTagIdentifier(sub)
	if err != nil {
		return TLV{}, mkerrf(r.Type().String(), " Packet.TLV: error reading tag: ", err.Error())
	}

	// Advance offset by identifier length.
	r.SetOffset(r.Offset() + idLen)

	// If there's an override in options, adjust.
	if opts != nil {
		if opts.HasTag() || opts.HasClass() {
			if opts.Explicit && !compound {
				return TLV{}, mkerr("Expected constructed TLV for explicit tagging override")
			}
			if opts.HasClass() {
				class = opts.Class()
			}
			if opts.HasTag() {
				tag = opts.Tag()
			}
		}
	}

	// Parse length.
	var length, lenLen int
	if length, lenLen, err = tlvVerifyLengthState(r, d); err != nil {
		return TLV{}, err
	}

	// Advance offset by the length bytes.
	r.SetOffset(r.Offset() + lenLen)

	// Use remaining data as value bytes.
	// Note: For definite lengths it may be necessary to slice exactly the given number
	// of bytes, but here we pass all remaining bytes.
	var tlv TLV
	switch r.Type() {
	case BER, CER, DER:
		tlv = r.Type().newTLV(class, tag, length, compound, d[r.Offset():]...)
	default:
		tlv = TLV{}
		err = errorRuleNotImplemented
	}

	return tlv, err
}

func tlvVerifyLengthState(r Packet, d []byte) (length, lenLen int, err error) {
	if length, lenLen, err = parseLength(d[r.Offset():]); err != nil {
		err = mkerrf(r.Type().String(),
			" Packet.TLV: error reading length: ", err.Error())
	} else if !r.Type().allowsIndefinite() && length < 0 {
		err = errorIndefiniteProhibited
	} else if r.Type() == DER {
		// DER canonical-form checks
		if lenLen > 1 && length < 0x80 {
			err = mkerr("DER: non-minimal length encoding")
		} else if lenLen > 2 && d[r.Offset()+1] == 0x00 {
			err = mkerr("DER: leading zero in length")
		}
	}

	return
}

func writeTLV(pkt Packet, t TLV, opts *Options) (err error) {
	var indefBytes []byte
	if (opts != nil && opts.Indefinite) || t.Length < 0 {
		if !pkt.Type().allowsIndefinite() {
			err = mkerrf(pkt.Type().String(), " forbids indefinite length")
			return
		}
		indefBytes = []byte{0x00, 0x00}
	} else if !t.Type().In(encodingRules...) {
		err = mkerrf(pkt.Type().String(), " Packet.WriteTLV: expected ",
			pkt.Type().String(), ", got ", t.Type().String())
		return
	}

	encoded := encodeTLV(t, opts)
	pkt.Append(encoded...)

	// Add end-of-contents for encoding rules that
	// permit indefinite value lengths if present.
	pkt.Append(indefBytes...)
	pkt.SetOffset(pkt.Len())

	return
}

func sizeTLV(tag int, length int) (size int) {
	size = 1
	if tag >= 31 {
		for i := tag; i > 0; i >>= 7 {
			size++
		}
	}

	size += 1
	if length >= 128 {
		size += 1
		for length > 255 {
			size++
			length >>= 8
		}
	}
	return
}

/*
encodeBase128Int returns the []byte encoding of an integer
as base-128 (for long-form tags).
*/
func encodeBase128Int(value int) []byte {
	var out []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		// Prepend if this isn't the last byte.
		if len(out) > 0 {
			b |= 0x80
		}
		out = append([]byte{b}, out...)
		if value == 0 {
			break
		}
	}
	return out
}

/*
readBase128Int returns the decoded base-128 integer,
used for tags >= 31.
*/
func readBase128Int(pkt Packet) (int, error) {
	result := 0
	for {
		if pkt.Offset() >= pkt.Len() {
			return 0, mkerr("truncated base-128 integer")
		}
		b := pkt.Data()[pkt.Offset()]
		pkt.SetOffset(pkt.Offset() + 1)
		result = (result << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	return result, nil
}

func encodeLengthInto(rule EncodingRule, dst *[]byte, n int) {
	switch rule {
	case BER:
		encodeBERLengthInto(dst, n)
	case CER:
		encodeCERLengthInto(dst, n)
	case DER:
		encodeDERLengthInto(dst, n)
	}
}
