package asn1plus

/*
utf8.go contains all types and methods pertaining to the ASN.1
UTF8 STRING.
*/

/*
UTF8String implements a flexible form of the ASN.1 UTF8 STRING (tag 12)
type per [ITU-T Rec. X.680].

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type UTF8String string

/*
Tag returns the integer constant [TagUTF8String].
*/
func (r UTF8String) Tag() int { return TagUTF8String }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r UTF8String) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r UTF8String) Len() int { return len(r) }

/*
defaultUTF8Constraint is the default validator that checks basic
UTF-8 validity via use of [utf8.ValidString].
*/
func defaultUTF8Constraint(s string) (err error) {
	if !utf8OK(s) {
		err = mkerr("invalid UTF8 in ASN.1 UTF8 STRING")
	}
	return
}

/*
NewUTF8String returns an instance of [UTF8String] alongside an error following an
attempt to marshal x.

The variadic constraints input allows for any number of override closures based upon
the Constraint[UTF8] signature.

One such situation that benefits from this feature in the real world is the UTF-8 range
in [ITU-T Rec. X.680] versus the constrained UTF8String characters defined in [§ 1.4 of
RFC 4512].

By default, the [utf8.ValidString] function is used for validation.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
func NewUTF8String(x any, constraints ...Constraint[UTF8String]) (u8 UTF8String, err error) {
	var raw string
	switch tv := x.(type) {
	case UTF8String:
		raw = string(tv)
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = mkerr("Invalid type for ASN.1 UTF8 STRING")
		return
	}

	if err = defaultUTF8Constraint(raw); err == nil {
		if len(constraints) > 0 {
			var group ConstraintGroup[UTF8String] = constraints
			err = group.Validate(UTF8String(raw))
		}

		if err == nil {
			u8 = UTF8String(raw)
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UTF8String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UTF8String) IsZero() bool { return len(r) == 0 }

func (r *UTF8String) read(pkt Packet, tlv TLV, opts Options) (err error) {
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
				*r = UTF8String(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}

	default:
		err = mkerr("Unsupported packet type for UTF8String decoding")
	}
	return
}

func (r UTF8String) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		if err = writeTLV(pkt, t.newTLV(0, r.Tag(), r.Len(), false, []byte(r)...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}
