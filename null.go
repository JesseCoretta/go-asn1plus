package asn1plus

/*
null.go contains all types and methods pertaining to the ASN.1
NULL type.
*/

/*
Null implements the ASN.1 NULL type (tag 5).

There is no constructor for instances of this type.
*/
type Null struct{}

/*
Tag returns the integer constant [TagNull].
*/
func (_ Null) Tag() int { return TagNull }

/*
Len always returns zero (0).
*/
func (_ Null) Len() int { return 0 }

/*
Null returns the string representation of the receiver instance.
*/
func (_ Null) String() string { return string(rune(0)) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (_ Null) IsPrimitive() bool { return true }

func (r Null) write(pkt Packet, opts *Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, 0, false), opts); err == nil {
			pkt.SetOffset(0)
		}
	}
	return
}

func (r *Null) read(pkt Packet, tlv TLV, opts *Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}
	switch pkt.Type() {
	case BER, DER:
		if _, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			if pkt.Offset()+tlv.Length > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
			} else if tlv.Length != 0 {
				err = mkerrf("Invalid NULL length: expected 0, got ", itoa(tlv.Length))
			} else {
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}
	return
}
