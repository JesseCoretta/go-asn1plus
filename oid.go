package asn1plus

/*
oid.go contains all types and methods pertaining to the ASN.1
OBJECT IDENTIFIER and RELATIVE-OID types.

DISCLAIMER: much of the OID logic is adapted from the now-archived
JesseCoretta/go-objectid, but with small improvements.
*/

import "math/big"

/*
ObjectIdentifier implements an unbounded ASN.1 OBJECT IDENTIFIER (tag 6),
which is convertible to both type [encoding/asn1.ObjectIdentifier] and
[crypto/x509.OID] types. See the [ObjectIdentifier.IntSlice] and
[ObjectIdentifier.Uint64Slice] methods for details.
*/
type ObjectIdentifier []Integer

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectIdentifier) String() (s string) {
	if !r.IsZero() {
		var x []string = make([]string, len(r))
		for i := 0; i < len(r); i++ {
			x[i] = r[i].String()
		}

		s = join(x, `.`)
	}
	return
}

/*
Eq returns a Boolean value indicative of an equality match between
the receiver and input [ObjectIdentifier] instances.
*/
func (r ObjectIdentifier) Eq(o ObjectIdentifier) bool {
	var ok bool
	if ok = r.Len() == o.Len(); ok {
		for i := 0; i < r.Len() && ok; i++ {
			ok = r[i].Eq(o[i])
		}
	}

	return ok
}

/*
Tag returns the integer constant [TagOID].
*/
func (r ObjectIdentifier) Tag() int { return TagOID }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r ObjectIdentifier) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r ObjectIdentifier) Len() int { return len(r) }

/*
IsZero returns a Boolean indicative of a nil receiver state.
*/
func (r *ObjectIdentifier) IsZero() (is bool) {
	if r != nil {
		is = r.Len() == 0
	}
	return
}

/*
NewObjectIdentifier returns an instance of [ObjectIdentifier] alongside
an error following an attempt to marshal x as an ASN.1 OBJECT IDENTIFIER.

Variadic input allows for slice mixtures of all of the following types,
with each treated as an individual [Integer] (number form) instance:

  - *[math/big.Int]
  - [Integer]
  - string
  - uint64
  - int64
  - int

If a string primitive is the only input option, it will be treated as a
complete [ObjectIdentifier] (e.g.: "1.3.6.1"). A single input value that
is NOT a string returns an error, as [ObjectIdentifier] instances MUST
have two (2) or more number form arcs at any given time.

If an [ObjectIdentifier] is the only input option, it is checked for
validity and returned without further processing.

[ObjectIdentifier]-focused instances of [Constraint] may be provided in
variadic form.
*/
func NewObjectIdentifier(x ...any) (r ObjectIdentifier, err error) {
	var _d ObjectIdentifier = make(ObjectIdentifier, 0)

	if len(x) == 1 {
		if slice, ok := x[0].(string); ok {
			r, err = newObjectIdentifierStr(slice)
			return
		} else if slice2, ok := x[0].(ObjectIdentifier); ok {
			if !slice2.Valid() {
				err = mkerr("Invalid ASN.1 OBJECT IDENTIFIER")
			} else {
				r = slice2
			}
			return
		} else {
			err = mkerr("An OID must have two (2) or more number forms")
			return
		}
	}

	var constraints ConstraintGroup[ObjectIdentifier]

	for i := 0; i < len(x) && err == nil; i++ {
		var nf Integer
		switch tv := x[i].(type) {
		case *big.Int, Integer, string, int64, uint64, int:
			nf, err = NewInteger(tv)
		case Constraint[ObjectIdentifier]:
			constraints = append(constraints, tv)
		default:
			err = mkerr("Unsupported slice type for ASN.1 OBJECT IDENTIFIER")
		}

		if nf.Lt(Integer{big: true, bigInt: newBigInt(0)}) {
			err = mkerr("Number form values cannot be negative")
			break
		}

		_d = append(_d, nf)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[ObjectIdentifier] = constraints
		err = group.Validate(_d)
	}

	if err == nil {
		r = _d
	}

	return
}

func newObjectIdentifierStr(dot string) (r ObjectIdentifier, err error) {
	if !isNumericOID(dot) {
		err = mkerr("Invalid OID cannot be processed " + dot)
		return
	}

	z := split(dot, `.`)
	_d := make(ObjectIdentifier, len(z))

	for j := 0; j < len(z) && err == nil; j++ {
		var nf Integer
		if nf, err = NewInteger(z[j]); err == nil {
			_d[j] = nf
		}
	}

	if err == nil {
		r = _d
	}

	return
}

func (r ObjectIdentifier) write(pkt Packet, opts Options) (n int, err error) {
	if r.Len() < 2 {
		err = mkerr("Length below encoding minimum")
		return
	}

	var content []byte
	var start int

	// The first two arcs are encoded together if possible.
	firstArc := r[0].Big()
	secondArc := r[1].Big()
	forty := newBigInt(40)

	if secondArc.Cmp(forty) <= 0 { // secondArc <= 40
		combined := new(big.Int).Mul(firstArc, forty)
		combined.Add(combined, secondArc)
		combinedBytes := combined.Bytes()
		if len(combinedBytes) == 0 {
			content = append(content, 0x00)
		} else {
			content = append(content, combinedBytes...)
		}
		start = 2
	} else {
		if firstArc.Uint64() != 2 {
			err = mkerr("Only joint-iso-itu-t(2) OIDs allow second-level arcs > 39")
			return
		}
		start = 1
	}

	// Encode the remaining arcs using VLQ.
	for i := start; i < len(r); i++ {
		content = append(content, encodeVLQ(r[i].Big().Bytes())...)
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

func (r *ObjectIdentifier) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil DER packet")
	}
	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Unsupported packet type for OID decoding")
	}
	return
}

func (r *ObjectIdentifier) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err != nil {
		return
	}

	var i int = 0
	subidentifier := newBigInt(0)

	*r = make(ObjectIdentifier, 0)
	for i < len(data) {
		for {
			subidentifier.Lsh(subidentifier, 7)
			subidentifier.Add(subidentifier, newBigInt(int64(data[i]&0x7F)))
			if data[i]&0x80 == 0 {
				break
			}
			i++
			if i >= len(data) {
				return mkerr("Truncated OID subidentifier")
			}
		}
		i++ // move past the last octet for the current subidentifier
		var arc Integer
		if subidentifier.IsInt64() {
			arc = Integer{
				big:    false,
				native: subidentifier.Int64(),
				bigInt: nil,
			}
		} else {
			arc = Integer{
				big:    true,
				native: 0,
				bigInt: subidentifier,
			}
		}
		*r = append(*r, arc)
		subidentifier = newBigInt(0)
	}
	if len(*r) > 0 {
		r.decodeFirstArcs(data[0])
	}

	return
}

func (r *ObjectIdentifier) decodeFirstArcs(b byte) {
	var firstArc *big.Int
	var secondArc *big.Int

	var forty *big.Int = newBigInt(40)
	var eighty *big.Int = newBigInt(80)

	if (*r)[0].Big().Cmp(newBigInt(80)) < 0 {
		firstArc = newBigInt(0).Div((*r)[0].Big(), forty)
		secondArc = newBigInt(0).Mod((*r)[0].Big(), forty)
	} else {
		firstArc = newBigInt(2)
		if b >= 0x80 {
			// Handle large second-level arcs for joint-iso-itu-t(2)
			secondArc = newBigInt(0).Sub((*r)[0].Big(), firstArc)
			secondArc.Add(secondArc, firstArc)
		} else {
			secondArc = newBigInt(0).Sub((*r)[0].Big(), eighty)
		}
	}

	var farc, sarc Integer
	if secondArc.IsInt64() {
		sarc = Integer{native: secondArc.Int64()}
	} else {
		sarc = Integer{big: true, bigInt: secondArc}
	}

	if firstArc.IsInt64() {
		farc = Integer{native: firstArc.Int64()}
	} else {
		farc = Integer{big: true, bigInt: firstArc}
	}

	(*r)[0] = sarc
	*r = append(ObjectIdentifier{farc}, *r...)
}

/*
IntSlice returns slices of integer values and an error. The integer values are based
upon the contents of the receiver. Note that if any single arc number overflows int,
a zero slice is returned.

Successful output can be cast as an instance of [encoding/asn1.ObjectIdentifier], if desired.
*/
func (r ObjectIdentifier) IntSlice() (slice []int, err error) {
	if r.IsZero() {
		err = mkerr("Nil receiver")
		return
	} else if r.Len() < 2 {
		err = mkerr("An OID must have two (2) or more number forms")
		return
	}

	var t []int
	for i := 0; i < len(r) && err == nil; i++ {
		var n int
		if n, err = atoi(r[i].String()); err == nil {
			t = append(t, n)
		}
	}

	if len(t) > 0 && err == nil {
		slice = t[:]
	}

	return
}

/*
Uint64Slice returns slices of uint64 values and an error. The uint64
values are based upon the contents of the receiver.

Note that if any single arc number overflows uint64, a zero slice is
returned alongside an error.

Successful output can be cast as an instance of [crypto/x509.OID], if
desired.
*/
func (r ObjectIdentifier) Uint64Slice() (slice []uint64, err error) {
	if r.IsZero() {
		err = mkerr("Nil receiver")
		return
	} else if r.Len() < 2 {
		err = mkerr("An OID must have two (2) or more number forms")
		return
	}

	var t []uint64
	for i := 0; i < len(r) && err == nil; i++ {
		var n uint64
		if n, err = puint(r[i].String(), 10, 64); err == nil {
			t = append(t, n)
		}
	}
	if len(t) > 0 && err == nil {
		slice = t[:]
	}

	return
}

/*
Index returns the Nth index from the receiver, alongside a Boolean
value indicative of success. This method supports the use of negative
indices.
*/
func (r ObjectIdentifier) Index(idx int) (a Integer, ok bool) {
	if L := len(r); L > 0 {
		if idx < 0 {
			a = r[0]
			if x := L + idx; x >= 0 {
				a = r[x]
			}
		} else if idx > L {
			a = r[L-1]
		} else if idx < L {
			a = r[idx]
		}
		ok = !a.IsZero()
	}

	return
}

/*
Valid returns a Boolean value indicative of the following:

  - Receiver's length is greater than or equal to two (2) slice members, AND ...
  - The first slice in the receiver contains an unsigned decimal value that is less than three (3)
*/
func (r ObjectIdentifier) Valid() (is bool) {
	if !r.IsZero() {
		is = (r[0].Lt(Integer{big: true, bigInt: newBigInt(3)}) &&
			r[0].Ge(Integer{big: true, bigInt: newBigInt(0)})) && r.Len() >= 2
	}

	return
}

/*
encodeVLQ returns the VLQ -- or Variable Length Quantity -- encoding of
the raw input value.
*/
func encodeVLQ(b []byte) []byte {
	// Create a new big.Int from the input bytes.
	n := new(big.Int).SetBytes(b)
	// If n is zero, then by VLQ rules we want to return a single zero byte.
	if n.Sign() == 0 {
		return []byte{0x00}
	}

	// Preallocate a small buffer. For typical OID arc values, 16 bytes is more than enough.
	var buf [16]byte
	i := len(buf) // We'll fill the buffer from right to left.
	base := newBigInt(128)
	remainder := new(big.Int)
	zero := newBigInt(0)

	// Loop until we've reduced the big.Int to zero.
	for n.Cmp(zero) > 0 {
		// DivMod updates n to the quotient and returns the remainder.
		n.DivMod(n, base, remainder)
		i-- // move back one position in the buffer

		// The lower 7 bits of the current VLQ byte are the remainder.
		// For all but the last (most significant) byte, we set the highest bit.
		byteVal := byte(remainder.Uint64())
		if len(buf)-i > 1 {
			byteVal |= 0x80
		}

		buf[i] = byteVal
	}

	// Return only the portion of the buffer that we used.
	// This slice is in the correct order.
	return buf[i:]
}

func isNumericOID(id string) bool {
	if !isValidOIDPrefix(id) {
		return false
	}

	var last rune
	for i, c := range id {
		switch {
		case c == '.':
			if last == c {
				return false
			} else if i == len(id)-1 {
				return false
			}
			last = '.'
		case ('0' <= c && c <= '9'):
			last = c
			continue
		}
	}

	return true
}

func isValidOIDPrefix(id string) bool {
	slices := split(id, `.`)
	if len(slices) < 2 {
		return false
	}

	root, err := atoi(slices[0])
	if err != nil {
		return false
	}
	if !(0 <= root && root <= 2) {
		return false
	}

	var sub int
	if sub, err = atoi(slices[1]); err != nil {
		return false
	} else if !(0 <= sub && sub <= 39) && root != 2 {
		return false
	}

	return true
}

/*
RelativeOID implements the ASN.1 RELATIVE-OID type (tag 13).
*/
type RelativeOID []Integer

/*
NewRelativeOID returns an instance of [RelativeOID] alongside an
error following an attempt to marshal x.
*/
func NewRelativeOID(x ...any) (rel RelativeOID, err error) {
	var _d RelativeOID = make(RelativeOID, 0)

	if len(x) == 1 {
		if slice, ok := x[0].(string); ok {
			ap := []any{}
			for _, s := range split(slice, `.`) {
				ap = append(ap, s)
			}
			rel, err = NewRelativeOID(ap...)
			return
		} else if roid, ok2 := x[0].(RelativeOID); ok2 {
			rel, err = NewRelativeOID([]Integer(roid))
			return
		}
	}

	for i := 0; i < len(x) && err == nil; i++ {
		var nf Integer
		switch tv := x[i].(type) {
		case *big.Int, Integer, string, int64, uint64, int:
			nf, err = NewInteger(tv)
		default:
			err = mkerr("Unsupported slice type for ASN.1 RELATIVE-OID")
		}

		if nf.Lt(Integer{big: true, bigInt: newBigInt(0)}) {
			err = mkerr("Number form values cannot be negative")
			break
		}

		_d = append(_d, nf)
	}

	if err == nil {
		rel = _d
	}

	return

}

/*
Tag returns the integer constant [TagRelativeOID].
*/
func (r RelativeOID) Tag() int { return TagRelativeOID }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r RelativeOID) IsPrimitive() bool { return true }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *RelativeOID) IsZero() bool { return r == nil }

/*
Absolute returns a complete [ObjectIdentifier] instance by appending the
receiver instance to the input [ObjectIdentifier].
*/
func (r RelativeOID) Absolute(base ObjectIdentifier) ObjectIdentifier {
	abs := make(ObjectIdentifier, len(base)+len(r))
	copy(abs, base)
	copy(abs[len(base):], r)
	return abs
}

/*
String returns the string representation of the receiver instance.
*/
func (r RelativeOID) String() string {
	var s []string
	for i := 0; i < len(r); i++ {
		s = append(s, r[i].String())
	}

	return join(s, `.`)
}

/*
Len returns the integer length of the receiver instance.
*/
func (r RelativeOID) Len() int { return len(r) }

func (r RelativeOID) write(pkt Packet, opts Options) (n int, err error) {
	if len(r) < 1 {
		return 0, mkerr("Relative OID must have at least one arc")
	}

	var content []byte
	for i := 0; i < r.Len(); i++ {
		content = append(content, encodeVLQ(r[i].Big().Bytes())...)
	}

	if len(content) >= 128 {
		return 0, mkerr("Relative OID content too long")
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

func (r *RelativeOID) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		return mkerr("Nil DER packet")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	default:
		err = mkerr("Encoding rule not implemented")
	}

	return
}

func (r *RelativeOID) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err != nil {
		return
	}

	if pkt.Len()-int(data[1]) != len(data) {
		err = mkerr("Length of bytes does not match the indicated length: " +
			itoa(pkt.Len()-int(data[1])) + "/" + itoa(len(data)))
		return
	}

	pkt.SetOffset(pkt.Offset() + 2 + int(data[1]))

	var i int = 0
	subidentifier := newBigInt(0)
	*r = make(RelativeOID, 0)

	// Decode each arc from the VLQ-encoded data.
	for i < len(data) {
		for {
			subidentifier.Lsh(subidentifier, 7)
			subidentifier.Add(subidentifier, newBigInt(int64(data[i]&0x7F)))
			if data[i]&0x80 == 0 {
				break
			}
			i++
			if i >= len(data) {
				err = mkerr("Truncated Relative OID subidentifier")
				break
			}
		}
		i++ // Move past the final byte for this arc.
		var arc Integer
		if subidentifier.IsInt64() {
			arc = Integer{big: false, native: subidentifier.Int64(), bigInt: nil}
		} else {
			arc = Integer{big: true, native: 0, bigInt: subidentifier}
		}
		*r = append(*r, arc)
		subidentifier = newBigInt(0) // Reset for the next arc.
	}
	return
}
