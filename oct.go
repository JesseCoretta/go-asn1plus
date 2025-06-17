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
	case OctetString:
		str = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 OCTET STRING")
	}

	runes := []rune(str)
	for i := 0; i < len(runes) && err == nil; i++ {
		if !(0x0000 <= runes[i] && runes[i] <= 0x00FF) {
			err = mkerrf("Invalid character ", string(runes[i]), " in string")
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[OctetString] = constraints
		err = group.Validate(OctetString(str))
	}

	if err == nil {
		oct = OctetString(str)
	}

	return
}

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

func (r OctetString) write(pkt Packet, opts Options) (n int, err error) {

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

func (r *OctetString) read(pkt Packet, tlv TLV, opts Options) (err error) {
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
				*r = OctetString(data)
				pkt.SetOffset(pkt.Offset() + lt)
			}
		}
	}

	return
}
