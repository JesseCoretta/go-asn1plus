package asn1plus

/*
ns.go contains all types and methods pertaining to the ASN.1
NUMERIC STRING type.
*/

import "reflect"

/*
NumericString implements the ASN.1 NUMERICSTRING type per [ITU-T Rec. X.680]:

	Digits     0, 1, ... 9
	Space

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type NumericString string

/*
Tag returns the integer constant [TagNumericString].
*/
func (r NumericString) Tag() int { return TagNumericString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r NumericString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r NumericString) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NumericString) IsZero() bool { return len(r) == 0 }

/*
NewNumericString returns an instance of [NumericString] alongside
an error following an attempt to marshal x.
*/
func NewNumericString(x any, constraints ...Constraint[NumericString]) (ns NumericString, err error) {
	var raw string
	if raw, err = convertToNumericString(x); err == nil {
		// Validate that raw contains only digits and space.
		for _, c := range raw {
			if !(c == ' ' || (c >= '0' && c <= '9')) {
				err = mkerr("Illegal character for ASN.1 NUMERICSTRING: " + string(c))
				break
			}
		}

		if len(constraints) > 0 && err == nil {
			var group ConstraintGroup[NumericString] = constraints
			err = group.Validate(NumericString(raw))
		}

		if err == nil {
			ns = NumericString(raw)
		}
	}
	return
}

func convertToNumericString(x any) (str string, err error) {
	// Do an explicit check for string first.
	if s, ok := x.(string); ok {
		if len(s) == 0 {
			err = mkerr("ASN.1 NUMERICSTRING is zero")
			return
		}
		str = s
		return
	} else if ns, ok := x.(NumericString); ok {
		if len(ns) == 0 {
			err = mkerr("ASN.1 NUMERICSTRING is zero")
			return
		}
		str = ns.String()
		return
	}

	// Otherwise, use reflection on numeric types.
	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := v.Int()
		if i < 0 {
			err = mkerr("Illegal sign (-) for ASN.1 NUMERICSTRING")
		} else {
			str = fmtInt(i, 10)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		str = fmtUint(v.Uint(), 10)
	default:
		err = mkerr("Invalid type for ASN.1 NUMERICSTRING")
	}

	return
}

func (r NumericString) write(pkt Packet, opts Options) (n int, err error) {
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

func (r *NumericString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		var data []byte
		if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
			if pkt.Offset()+tlv.Length > pkt.Len() {
				err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
			} else {
				*r = NumericString(data)
				pkt.SetOffset(pkt.Offset() + tlv.Length)
			}
		}
	}

	return
}
