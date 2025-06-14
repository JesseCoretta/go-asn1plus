package asn1plus

/*
us.go contains all types and methods pertaining to the ASN.1
UNIVERSAL STRING type.
*/

import "encoding/binary"

/*
UniversalString implements the UCS-4 ASN.1 UNIVERSAL STRING (tag 28).
*/
type UniversalString string

/*
Tag returns the integer constant [TagUniversalString].
*/
func (r UniversalString) Tag() int { return TagUniversalString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r UniversalString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r UniversalString) Len() int { return len(r) }

func NewUniversalString(x any, constraints ...Constraint[UniversalString]) (UniversalString, error) {
	var (
		us  UniversalString
		raw string
		err error
	)

	switch tv := x.(type) {
	case UniversalString:
		raw = string(tv)
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = mkerr("Invalid type for ASN.1 UNIVERSAL STRING")
		return us, err
	}

	if !utf8OK(raw) {
		err = mkerr("Invalid ASN.1 UNIVERSAL STRING: failed UTF8 checks")
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[UniversalString] = constraints
		err = group.Validate(UniversalString(raw))
	}

	if err == nil {
		us = UniversalString(raw)
	}

	return us, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }

func (r UniversalString) write(pkt Packet, opts Options) (n int, err error) {
	runes := []rune(r)
	content := make([]byte, 4*len(runes))
	for i, ru := range runes {
		binary.BigEndian.PutUint32(content[i*4:(i+1)*4], uint32(ru))
	}

	switch t := pkt.Type(); t {
	case BER, DER:
		off := pkt.Offset()
		if err = writeTLV(pkt, t.newTLV(0, r.Tag(), len(content), false, content...), opts); err == nil {
			n = pkt.Offset() - off
		}
	}
	return
}

func (r *UniversalString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for UNIVERSAL STRING decoding")
	}

	return
}

func (r *UniversalString) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			pkt.SetOffset(pkt.Offset() + tlv.Length)

			// The content must be a multiple of 4 bytes (each rune is 4 bytes in UCS-4).
			if len(data)%4 != 0 {
				err = mkerr("invalid UNIVERSAL STRING length: not a multiple of 4 bytes")
				return
			}

			var runes []rune
			for i := 0; i < len(data); i += 4 {
				rVal := binary.BigEndian.Uint32(data[i : i+4])
				runes = append(runes, rune(rVal))
			}

			*r = UniversalString(string(runes))
		}
	}

	return
}
