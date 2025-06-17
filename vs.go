package asn1plus

/*
vs.go contains all types and methods pertaining to the ASN.1
VISIBLE STRING type.
*/

/*
VisibleString implements the ASN.1 VISIBLE STRING type (tag 26).
Instances of this type may contain any ASCII characters which are
not control characters.
*/
type VisibleString string

/*
NewVisibleString returns an instance of [VisibleString] alongside
an error following an attempt to marshal x.
*/
func NewVisibleString(x any, constraints ...Constraint[VisibleString]) (VisibleString, error) {
	var (
		vs  VisibleString
		raw string
		err error
	)

	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case VisibleString:
		raw = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 VISIBLE STRING")
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		if char := rune(raw[i]); isCtrl(char) {
			err = mkerrf("Invalid character for ASN.1 VISIBLE STRING: #",
				itoa(int(char)), " (is control character)")
		}
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[VisibleString] = constraints
		err = group.Validate(VisibleString(raw))
	}

	if err == nil {
		vs = VisibleString(raw)
	}

	return vs, err
}

/*
Len returns the integer length of the receiver instance.
*/
func (r VisibleString) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *VisibleString) IsZero() bool { return &r == nil }

/*
String returns the string representation of the receiver instance.
*/
func (r VisibleString) String() string { return string(r) }

/*
Tag returns the integer constant [TagVisibleString].
*/
func (r VisibleString) Tag() int { return TagVisibleString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r VisibleString) IsPrimitive() bool { return true }

func (r VisibleString) write(pkt Packet, opts Options) (n int, err error) {
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

func (r *VisibleString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			if pkt.Offset()+tlv.Length > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
			} else {
				*r = VisibleString(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}
