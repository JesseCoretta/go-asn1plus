package asn1plus

/*
enum.go contains all types and methods pertaining to the ASN.1
ENUMERATED type.
*/

/*
Enumeration implements a map of [Enumerated] string values. This
is not a standard type and is implemented merely for convenience.
*/
type Enumeration map[Enumerated]string

/*
Name scans the receiver instance to determine the string name for the
input [Enumerated] value.
*/
func (r Enumeration) Name(e Enumerated) string {
	var n string = "unknown (" + itoa(int(e)) + ")"
	if name, ok := r[e]; ok {
		n = name
	}
	return n
}

/*
Enumerated implements the ASN.1 ENUMERATED type (tag 10).
*/
type Enumerated int

/*
Tag returns the integer constant [TagEnum].
*/
func (r Enumerated) Tag() int { return TagEnum }

/*
Enumerated returns the string representation of the receiver instance.
*/
func (r Enumerated) String() string { return itoa(int(r)) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (r Enumerated) IsPrimitive() bool { return true }

/*
NewEnumerated returns an instance of [Enumerated].
*/
func NewEnumerated(x any, constraints ...Constraint[Enumerated]) (enum Enumerated, err error) {
	var e int
	switch tv := x.(type) {
	case int:
		e = tv
	case Enumerated:
		e = int(tv)
	default:
		err = mkerr("Invalid type for ASN.1 ENUMERATED")
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Enumerated] = constraints
		err = group.Validate(Enumerated(e))
	}

	if err == nil {
		enum = Enumerated(e)
	}

	return
}

/*
Int returns the integer representation of the receiver instance.
*/
func (e Enumerated) Int() int {
	return int(e)
}

func (r Enumerated) write(pkt Packet, opts Options) (n int, err error) {
	data := encodeNativeInt(int(r))
	if opts.Tag == -1 {
		opts.Tag = r.Tag()
	}

	switch t := pkt.Type(); t {
	case BER, DER:
		l := encodeLength(t, sizeOfInt(int(r)))
		ct := byte(opts.Class + opts.Tag)
		head := append([]byte{ct}, l...)
		pkt.Append(append(head, data...)...)
		n = len(data)
	}
	return
}

func (r *Enumerated) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for ASN.1 ENUMERATED decoding")
	}

	return
}

func (r *Enumerated) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	class, tag := ClassUniversal, r.Tag()
	if validClass(opts.Class) {
		class = opts.Class
	}

	if opts.Tag >= 0 {
		tag = opts.Tag
	}

	if class != tlv.Class || tag != tlv.Tag || tlv.Compound {
		err = mkerr("Invalid ASN.1 ENUMERATED header in " + pkt.Type().String() + " packet")
	} else if pkt.Offset()+tlv.Length > pkt.Len() {
		err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
	} else {
		content := pkt.Data()[pkt.Offset() : pkt.Offset()+tlv.Length]
		pkt.SetOffset(pkt.Offset() + tlv.Length)
		var dec int
		if dec, err = decodeNativeInt(content); err == nil {
			*r = Enumerated(dec)
		}
	}

	return
}
