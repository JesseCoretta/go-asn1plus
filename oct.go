package asn1plus

/*
oct.go contains all types and methods pertaining to the ASN.1
OCTET STRING type.
*/

/*
OctetString returns an instance of [OctetString] alongside an error
following an attempt to marshal x.
*/
func NewOctetString(x any, constraints ...Constraint[OctetString]) (oct OctetString, err error) {
	var str string

	switch tv := x.(type) {
	case []byte:
		str = string(tv)
	case string:
		str = tv
	case Primitive:
		str = tv.String()
	default:
		err = errorBadTypeForConstructor("OCTET STRING", x)
		return
	}

	_oct := OctetString(str)
	err = OctetSpec(_oct)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[OctetString] = constraints
		err = group.Validate(_oct)
	}

	if err == nil {
		oct = _oct
	}

	return
}

/*
OctetSpec implements the formal [Constraint] specification for [OctetString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var OctetSpec Constraint[OctetString]

/*
OctetString implements the ASN.1 OCTET STRING type (tag 4).
*/
type OctetString []byte

/*
Tag returns the integer constant [TagOctetString].
*/
func (r OctetString) Tag() int { return TagOctetString }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *OctetString) IsZero() bool { return r == nil }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r OctetString) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string { return string(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r OctetString) Len() int {
	var l int
	if &r != nil {
		l = len(r)
	}
	return l
}

// ----------------------------------------------------------------
// 1) CER‐writer: unchanged
func cerSegmentedOctetStringWrite[T TextLike](
	c *textCodec[T],
	pkt Packet,
	opts *Options,
) (written int, err error) {
	const maxSegSize = 1000

	// get raw bytes
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
	hdr := []byte{byte(TagOctetString) | 0x20, 0x80}
	pkt.Append(hdr...)
	written += len(hdr)

	// break into 1000‐byte primitive‐OCTET‐STRING TLVs
	for off := 0; off < len(wire); off += maxSegSize {
		end := off + maxSegSize
		if end > len(wire) {
			end = len(wire)
		}
		prim := pkt.Type().newTLV(
			ClassUniversal, TagOctetString,
			end-off, false,
			wire[off:end]...,
		)
		enc := encodeTLV(prim, nil)
		pkt.Append(enc...)
		written += len(enc)
	}

	// EOC
	pkt.Append(0x00, 0x00)
	written += 2

	return written, nil
}

func cerSegmentedOctetStringRead[T TextLike](
	c *textCodec[T],
	pkt Packet,
	outer TLV,
	opts *Options,
) error {
	// a) validate the outer TLV
	if outer.Class != ClassUniversal ||
		outer.Tag != TagOctetString ||
		!outer.Compound ||
		outer.Length != -1 {
		return mkerr("cerSegmentedOctetStringRead: not CER indefinite OCTET STRING")
	}

	// b) drive a sub‐packet over outer.Value (all inner‐TLV bytes)
	sub := pkt.Type().New(outer.Value...)
	sub.SetOffset(0)

	// c) peel off each primitive OCTET‐STRING segment
	var full []byte
	for sub.HasMoreData() {
		// parse inner TLV (moves offset to start-of-value)
		seg, err := sub.TLV()
		if err != nil {
			return err
		}

		// break on EOC if it sneaks in (length=0, tag=0)
		if seg.Class == ClassUniversal && seg.Tag == 0 && seg.Length == 0 {
			break
		}

		// collect the payload
		full = append(full, seg.Value...)

		// now skip *past* the value bytes we just read
		sub.SetOffset(sub.Offset() + seg.Length)
	}

	// d) any decodeVerify hooks
	for _, verify := range c.decodeVerify {
		if err := verify(full); err != nil {
			return err
		}
	}

	// e) decodeHook + constrain + assign
	var val T
	if c.decodeHook != nil {
		var err error
		val, err = c.decodeHook(full)
		if err != nil {
			return err
		}
	} else {
		// copy to avoid aliasing original slice
		val = T(append([]byte(nil), full...))
	}
	if err := c.cg.Constrain(val); err != nil {
		return err
	}
	c.val = val
	return nil
}

func init() {
	RegisterTextAlias[OctetString](TagOctetString, nil, nil, nil, OctetSpec)
	OctetSpec = func(o OctetString) (err error) {
		for _, r := range []rune(o.String()) {
			if r > 0x00FF {
				err = mkerrf("Invalid character '", string(r), "' (>0x00FF) in OCTET STRING")
				break
			}
		}
		return
	}
}
