package asn1plus

/*
tlv.go contains all types, methods and functions for the
Type-Length-Value type.
*/

import "bytes"

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
type are produced through the use of any [PDU] instance's "TLV()"
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

func encodeTLV(t TLV, opts *Options) (out []byte) {
	debugEnter(
		newLItem(t.Class, "class"),
		newLItem(t.Compound, "compound"),
		newLItem(t.Tag, "tag"),
		newLItem(t.Length, "len"),
		opts,
	)

	defer func() {
		// on exit, log the output length and bytes
		debugEvent(EventExit|EventTLV,
			newLItem(len(out), "encoded TLV length"),
			newLItem(out, "encoded TLV bytes"),
		)
	}()

	bufPtr := getBuf()
	b := *bufPtr
	b = b[:0]

	id := byte(t.Class << 6)
	if t.Compound || (opts != nil && opts.Explicit) {
		id |= 0x20
	}

	debugEvent(EventTrace|EventTLV,
		newLItem(id, "identifier byte"),
	)

	tagVal := t.Tag
	if opts != nil && opts.HasTag() {
		tagVal = opts.Tag()
	}

	debugTLV(newLItem([]int{t.Tag, tagVal}, "tag orig/new"))

	if tagVal < 31 {
		b = append(b, id|byte(tagVal))
		debugEvent(EventTrace|EventTLV,
			newLItem(id|byte(tagVal), "single-byte tag"),
		)
	} else {
		b = append(b, id|0x1F)
		enc := encodeBase128Int(tagVal)
		debugEvent(EventTrace|EventTLV,
			newLItem(id|0x1F, "high-tag marker"),
			newLItem(enc, "base-128 tag bytes"),
		)
		b = append(b, enc...)
	}

	if tagVal < 0 {
		panic("encodeTLV: negative tag reached encoder")
	}

	b4 := len(b)
	encodeLengthInto(t.Type(), &b, t.Length)
	debugTLV(
		newLItem(t.Length, "value length"),
		newLItem(len(b)-b4, "length field size"),
	)

	b = append(b, t.Value...)

	debugEvent(EventTrace|EventTLV,
		newLItem(len(t.Value), "written"),
		newLItem(t.Value, "bytes"))

	out = make([]byte, len(b))
	copy(out, b)
	*bufPtr = b[:0]
	putBuf(bufPtr)

	return out
}

func getTLVResolveOverride(class, tag int, compound bool, opts *Options) (int, int, error) {
	var err error
	if opts != nil && (opts.HasClass() || opts.HasTag()) {
		if opts.Explicit && !compound {
			err = mkerr("Expected constructed TLV for explicit tagging override")
		} else {
			if opts.HasClass() {
				class = opts.Class()
			}
			if opts.HasTag() {
				tag = opts.Tag()
			}
		}
	}

	debugEvent(EventTrace|EventTLV,
		newLItem(class, "class override"),
		newLItem(tag, "tag override"))

	return class, tag, err
}

func getTLV(r PDU, opts *Options) (tlv TLV, err error) {
	debugEvent(EventEnter|EventTLV,
		newLItem(r, "PDU"),
		opts,
	)

	defer func() {
		debugEvent(EventExit|EventTLV,
			newLItem(tlv, "tlv"),
			newLItem(err),
		)
	}()

	if r.Offset() >= r.Len() {
		err = mkerrf(r.Type().String(), " PDU.TLV: no data available at offset ",
			itoa(r.Offset()), " (len:", itoa(r.Len()), ")")
		return
	}

	d := r.Data()
	debugEvent(EventTrace|EventTLV,
		newLItem(len(d), "len"),
		newLItem(d, "bytes"),
	)

	sub := d[r.Offset():]
	debugEvent(EventTrace|EventTLV,
		newLItem(sub, "chopped"),
	)

	// Parse class.
	var (
		tag,
		class,
		idLen,
		lenLen,
		length int
		compound bool
	)

	if class, err = parseClassIdentifier(sub); err != nil {
		return
	}
	debugEvent(EventTrace|EventTLV, newLItem(class, "class"))

	compound, _ = parseCompoundIdentifier(sub)
	debugEvent(EventTrace|EventTLV, newLItem(compound, "compound"))

	if tag, idLen, err = parseTagIdentifier(sub); err != nil {
		err = mkerrf(r.Type().String(), " PDU.TLV: error reading tag: ", err.Error())
		return
	}

	debugEvent(EventTrace|EventTLV,
		newLItem(tag, "tag"),
		newLItem(idLen, "idLen"))

	debugEvent(EventTrace|EventTLV,
		newLItem([]int{r.Offset(), r.Offset() + idLen}, "offset orig/new"))

	r.SetOffset(r.Offset() + idLen)

	// restore implicit/explicit override here
	if class, tag, err = getTLVResolveOverride(class, tag, compound, opts); err != nil {
		return
	}

	// Parse length.
	if length, lenLen, err = tlvVerifyLengthState(r, d); err != nil {
		return
	}

	debugEvent(EventTrace|EventTLV,
		newLItem([]int{r.Offset(), r.Offset() + lenLen}, "offset orig/new"))

	r.SetOffset(r.Offset() + lenLen)

	if !r.Type().In(encodingRules...) {
		err = errorRuleNotImplemented
		return
	}

	start := r.Offset()
	var valueBytes []byte

	if length >= 0 {
		// definite-length
		end := start + length
		if end > len(d) {
			err = mkerrf("TLV: unexpected truncation of definite length value (", itoa(end), " > ", itoa(len(d)), ")")
			return
		}
		valueBytes = d[start:end]
		debugEvent(EventTrace|EventTLV,
			newLItem(start, "value start"),
			newLItem(end, "value end"),
		)
	} else {
		// indefinite-length (BER)
		buf := d[start:]
		eocIdx := bytes.Index(buf, []byte{0x00, 0x00})
		if eocIdx < 0 {
			err = mkerr("TLV: missing end-of-contents for indefinite value")
			return
		}
		valueBytes = buf[:eocIdx]
		debugEvent(EventTrace|EventTLV,
			newLItem(start, "value start"),
			newLItem(eocIdx, "EOC index"),
		)
	}

	switch r.Type() {
	case BER, CER, DER:
		tlv = r.Type().newTLV(class, tag, length, compound, valueBytes...)
		debugTLV(tlv)
	}

	return
}

func tlvVerifyLengthState(r PDU, d []byte) (length, lenLen int, err error) {
	debugEvent(EventEnter|EventTLV,
		newLItem(r, "PDU"),
		newLItem(d, "bytes"))

	defer func() {
		debugEvent(EventExit|EventTLV,
			newLItem(length, "len"),
			newLItem(lenLen, "lenLen"),
			newLItem(err),
		)
	}()

	if length, lenLen, err = parseLength(d[r.Offset():]); err != nil {
		err = mkerrf(r.Type().String(),
			" PDU.TLV: error reading length: ", err.Error())
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

func writeTLV(pkt PDU, t TLV, opts *Options) (err error) {
	debugEvent(EventEnter|EventTLV,
		newLItem(pkt, "PDU"),
		newLItem(t, "tlv"),
		opts)

	defer func() {
		debugEvent(EventExit|EventTLV,
			newLItem(err))
	}()

	var indefBytes []byte
	if (opts != nil && opts.Indefinite) || t.Length < 0 {
		if !pkt.Type().allowsIndefinite() {
			err = mkerrf(pkt.Type().String(), " forbids indefinite length")
			return
		}
		indefBytes = []byte{0x00, 0x00}
	} else if !t.Type().In(encodingRules...) {
		err = mkerrf(pkt.Type().String(), " PDU.WriteTLV: expected ",
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

/*
readBase128Int returns the decoded base-128 integer,
used for tags >= 31.
*/
func readBase128Int(pkt PDU) (int, error) {
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

// encodeBase128Int builds the tag field in a fixed [10]byte buffer.
// It never allocates or shifts, just writes from the end down.
func encodeBase128Int(value int) []byte {
	var buf [10]byte
	i := len(buf) - 1
	buf[i] = byte(value & 0x7F)
	value >>= 7
	for value > 0 {
		i--
		buf[i] = byte(value&0x7F) | 0x80
		value >>= 7
	}
	return buf[i:]
}

func encodeLengthInto(rule EncodingRule, dst *[]byte, n int) {
	switch rule {
	case BER:
		encodeBERLengthInto(dst, n)
	case CER, DER:
		encodeBCDLengthInto(dst, n)
	}
}
