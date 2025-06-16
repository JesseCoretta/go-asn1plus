package asn1plus

/*
ia5.go contains all types and methods pertaining to the International
Alphabet No. 5 string.
*/

/*
IA5String implements the [ITU-T Rec. T.50] IA5 string (tag 22), supporting
the following character range from the International Alphabet No. 5:

	0x00 through 0xFF

[ITU-T Rec. T.50]: https://www.itu.int/rec/T-REC-T.50
*/
type IA5String string

/*
Len returns the integer length of the receiver instance.
*/
func (r IA5String) Len() int { return len(r) }

/*
Tag returns the integer constant [TagIA5String].
*/
func (r IA5String) Tag() int { return TagIA5String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive type.
*/
func (r IA5String) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r IA5String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r IA5String) IsZero() bool { return len(r) == 0 }

/*
IA5String returns an instance of [IA5String] alongside an error following
an attempt to marshal x.
*/
func NewIA5String(x any, constraints ...Constraint[IA5String]) (ia5 IA5String, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	case IA5String:
		raw = tv.String()
	default:
		err = mkerr("Invalid type for IA5String")
		return
	}

	err = checkIA5String(raw)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[IA5String] = constraints
		err = group.Validate(IA5String(raw))
	}

	if err == nil {
		ia5 = IA5String(raw)
	}

	return
}

func checkIA5String(raw string) (err error) {
	if len(raw) == 0 {
		err = mkerr("Invalid IA5 String (zero)")
		return
	}

	runes := []rune(raw)
	for i := 0; i < len(runes) && err == nil; i++ {
		var char rune = runes[i]
		if !(0x0000 <= char && char <= 0x00FF) {
			err = mkerr("Invalid IA5 String character: " + string(char))
		}
	}

	return
}

func (r *IA5String) read(pkt Packet, tlv TLV, opts Options) (err error) {
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
				*r = IA5String(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}

func (r IA5String) write(pkt Packet, opts Options) (n int, err error) {
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
