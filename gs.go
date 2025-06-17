package asn1plus

/*
gs.go contains all types and methods pertaining to the ASN.1
GRAPHIC STRING type.
*/

import "unicode"

/*
Deprecated: GraphicString implements the ASN.1 GRAPHIC STRING type (tag 25).

This type is implemented within this package for historical/legacy purposes
and should not be used in modern systems.
*/
type GraphicString string

/*
NewGraphicString returns an instance of [GraphicString] alongside an error
following attempt to marshal x.
*/
func NewGraphicString(x any, constraints ...Constraint[GraphicString]) (gs GraphicString, err error) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	case GraphicString:
		s = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 GRAPHIC STRING")
		return
	}

	_, err = scanGraphicStringChars(s)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[GraphicString] = constraints
		err = group.Validate(GraphicString(s))
	}

	if err == nil {
		gs = GraphicString(s)
	}

	return
}

func scanGraphicStringChars(x string) (gs string, err error) {
	for _, ch := range x {
		if ch < 128 {
			// For ASCII, only characters 33 through 126 are allowed.
			// For non-ASCII, allow only if printable and not control.
			if ch < 32 || ch > 126 || !isPrint(ch) || isCtrl(ch) {
				err = mkerr("Invalid ASN.1 GRAPHIC STRING character")
				break
			}
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
func (r GraphicString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r GraphicString) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r GraphicString) String() string { return string(r) }

/*
Tag returns the integer constant [TagGraphicString].
*/
func (r GraphicString) Tag() int { return TagGraphicString }

/*
IsPrimitive returns true, indicating the receiver instance is a
known ASN.1 primitive.
*/
func (r GraphicString) IsPrimitive() bool { return true }

func (r GraphicString) write(pkt Packet, opts *Options) (n int, err error) {
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

func (r *GraphicString) read(pkt Packet, tlv TLV, opts *Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}
	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	}
	return
}

func (r *GraphicString) readBER(pkt Packet, tlv TLV, opts *Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			// Validate each rune against the allowed graphic characters.
			for _, ch := range string(data) {
				if ch < 128 {
					// Only characters 33..126 allowed in ASCII.
					if ch < 33 || ch > 126 {
						return mkerr("Invalid ASN.1 GRAPHIC STRING character")
					}
				} else if !unicode.IsPrint(ch) || unicode.IsControl(ch) {
					return mkerr("Invalid ASN.1 GRAPHIC STRING character")
				}
			}
			*r = GraphicString(data)
			pkt.SetOffset(pkt.Offset() + tlv.Length)
		}
	}

	return
}
