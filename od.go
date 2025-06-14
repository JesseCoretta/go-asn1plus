package asn1plus

/*
od.go contains all types and methods pertaining to the ASN.1
OBJECT DESCRIPTOR type.
*/

/*
ObjectDescriptor implements the ASN.1 OBJECT DESCRIPTOR type (tag 7).
It operates under the same principals and constraints as the ASN.1
[GraphicString] type.
*/
type ObjectDescriptor string

/*
NewObjectDescriptor returns an instance of [ObjectDescriptor] alongside
an error following an attempt to marshal x.
*/
func NewObjectDescriptor(x any, constraints ...Constraint[ObjectDescriptor]) (ObjectDescriptor, error) {
	var (
		str string
		od  ObjectDescriptor
		err error
	)

	switch tv := x.(type) {
	case string:
		str = tv
	case []byte:
		str = string(tv)
	case ObjectDescriptor:
		str = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 OBJECT DESCRIPTOR")
		return od, err
	}

	_, err = scanGraphicStringChars(str)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[ObjectDescriptor] = constraints
		err = group.Validate(ObjectDescriptor(str))
	}

	if err == nil {
		od = ObjectDescriptor(str)
	}

	return od, err
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ObjectDescriptor) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectDescriptor) IsZero() bool { return len(r) == 0 }

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectDescriptor) String() string { return string(r) }

/*
Tag returns the integer constant [TagObjectDescriptor].
*/
func (r ObjectDescriptor) Tag() int { return TagObjectDescriptor }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r ObjectDescriptor) IsPrimitive() bool { return true }

func (r ObjectDescriptor) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		if err = writeTLV(pkt, t.newTLV(0, r.Tag(), r.Len(), false, []byte(r)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *ObjectDescriptor) read(pkt Packet, tlv TLV, opts Options) (err error) {
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
				*r = ObjectDescriptor(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}
