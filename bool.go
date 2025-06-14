package asn1plus

/*
bool.go contains all types and methods pertaining to the ASN.1
BOOLEAN type.
*/

/*
Boolean implements the ASN.1 BOOLEAN type.
*/
type Boolean bool

/*
Tag returns the integer constant one (1) for [TagBoolean].
*/
func (r Boolean) Tag() int { return TagBoolean }

/*
Byte returns the verisimilitude of the receiver instance expressed
as a byte: 0x0 for false, 0xFF for true.
*/
func (r Boolean) Byte() byte {
	var b byte
	if bool(r) {
		b = 0xFF
	}

	return b
}

/*
String returns the string representation of the receiver instance.
*/
func (r Boolean) String() string { return bool2str(bool(r)) }

/*
Bool returns the receiver instance cast as a native Go bool.
*/
func (r Boolean) Bool() bool { return bool(r) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (r Boolean) IsPrimitive() bool { return true }

/*
NewBoolean returns an instance of [Boolean] alongside an error following
an attempt to marshal x.
*/
func NewBoolean(x any, constraints ...Constraint[Boolean]) (b Boolean, err error) {
	switch tv := x.(type) {
	case bool:
		b = Boolean(tv)
	case *bool:
		if tv != nil {
			b = Boolean(*tv)
		}
	case string:
		var _b bool
		_b, err = pbool(tv)
		b = Boolean(_b)
	case int:
		b = Boolean(tv == 1)
	case byte:
		b = Boolean(tv == 0xFF)
	default:
		err = mkerr("Invalid type for ASN.1 BOOLEAN")
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Boolean] = constraints
		err = group.Validate(Boolean(b == true))
	}

	return b, err
}

func (r *Boolean) read(pkt Packet, tlv TLV, opts Options) (err error) {
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
				pkt.SetOffset(pkt.Offset() + 1)
				*r = Boolean(data[0] != 0)
			}
		}
	}

	return
}

func (r Boolean) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		if err = writeTLV(pkt, t.newTLV(0, r.Tag(), 1, false, r.Byte()), opts); err == nil {
			n = pkt.Offset() - off
		}
	}

	return
}
