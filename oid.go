package asn1plus

/*
oid.go contains all types and methods pertaining to the ASN.1
OBJECT IDENTIFIER and RELATIVE-OID types.

DISCLAIMER: much of the OID logic is adapted from the now-archived
JesseCoretta/go-objectid, but with small improvements.
*/

import (
	"math/big"
	"reflect"
	"unsafe"
)

/*
ObjectIdentifier implements an unbounded ASN.1 OBJECT IDENTIFIER (tag 6),
which is convertible to both type [encoding/asn1.ObjectIdentifier] and
[crypto/x509.OID] types. See the [ObjectIdentifier.IntSlice] and
[ObjectIdentifier.Uint64Slice] methods for details.
*/
type ObjectIdentifier []Integer

/*
ObjectIdentifierConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var ObjectIdentifierConstraintPhase = CodecConstraintDecoding

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
				err = primitiveErrorf("OBJECT IDENTIFIER: invalid value")
			} else {
				r = slice2
			}
			return
		} else {
			err = errorMinOIDArcs
			return
		}
	}

	var constraints ConstraintGroup

	for i := 0; i < len(x) && err == nil; i++ {
		var nf Integer
		switch tv := x[i].(type) {
		case *big.Int, Integer, string, int64, uint64, int:
			nf, err = NewInteger(tv)
		case func(any) error:
			constraints = append(constraints, Constraint(tv))
		default:
			err = errorBadTypeForConstructor("OBJECT IDENTIFIER", x[i])
		}

		if nf.Lt(Integer{big: true, bigInt: newBigInt(0)}) {
			err = primitiveErrorf("OBJECT IDENTIFIER: number form values cannot be negative")
			break
		}

		_d = append(_d, nf)
	}

	if len(constraints) > 0 && err == nil {
		err = constraints.Constrain(_d)
	}

	if err == nil {
		r = _d
	}

	return
}

func newObjectIdentifierStr(dot string) (r ObjectIdentifier, err error) {
	if !isNumericOID(dot) {
		err = primitiveErrorf("OBJECT IDENTIFIER: invalid OID ", dot)
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

func vlqEncodeBig(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	var buf [16]byte
	i := len(buf)
	tmp := newBigInt(0).Set(n)
	rem := newBigInt(0)

	for tmp.Sign() != 0 {
		tmp.DivMod(tmp, newBigInt(128), rem)
		i--
		b := byte(rem.Uint64())
		if len(buf)-i > 1 { // set continuation bit except on last octet
			b |= 0x80
		}
		buf[i] = b
	}
	return buf[i:]
}

/*
IntSlice returns slices of integer values and an error. The integer values are based
upon the contents of the receiver. Note that if any single arc number overflows int,
a zero slice is returned.

Successful output can be cast as an instance of [encoding/asn1.ObjectIdentifier], if desired.
*/
func (r ObjectIdentifier) IntSlice() (slice []int, err error) {
	if r.IsZero() {
		err = errorNilReceiver
		return
	} else if r.Len() < 2 {
		err = errorMinOIDArcs
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
		err = errorNilReceiver
		return
	} else if r.Len() < 2 {
		err = errorMinOIDArcs
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
RelativeOIDConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var RelativeOIDConstraintPhase = CodecConstraintDecoding

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

	for i := 0; i < len(x); i++ {
		var nf Integer
		switch tv := x[i].(type) {
		case *big.Int, Integer, string, int64, uint64, int:
			nf, err = NewInteger(tv)
		default:
			err = errorBadTypeForConstructor("RELATIVE-OID", x[i])
			break
		}

		if nf.Lt(Integer{big: true, bigInt: newBigInt(0)}) {
			err = primitiveErrorf("OBJECT IDENTIFIER: number form values cannot be negative")
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

type oidCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *oidCodec[T]) Tag() int          { return c.tag }
func (c *oidCodec[T]) IsPrimitive() bool { return true }
func (c *oidCodec[T]) String() string    { return "oidCodec" }
func (c *oidCodec[T]) getVal() any       { return c.val }
func (c *oidCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func toObjectIdentifier[T any](v T) ObjectIdentifier   { return *(*ObjectIdentifier)(unsafe.Pointer(&v)) }
func fromObjectIdentifier[T any](i ObjectIdentifier) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *oidCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch {
	case pkt.Type().In(BER, CER, DER):
		n, err = bcdOIDWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdOIDWrite[T any](c *oidCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			oid := toObjectIdentifier(c.val)
			if len(oid) < 2 {
				err = errorMinOIDArcs
				return
			}

			first, second := oid[0].Big(), oid[1].Big()
			if first.Cmp(newBigInt(0)) < 0 || first.Cmp(newBigInt(2)) > 0 {
				err = primitiveErrorf("OBJECT IDENTIFIER: first arc must be 0..2")
				return
			}

			if first.Cmp(newBigInt(2)) < 0 && second.Cmp(newBigInt(40)) >= 0 {
				err = primitiveErrorf("OBJECT IDENTIFIER: second arc must be 0..39 when first arc is 0 or 1")
				return
			}

			// first-two-arc compression
			combined := newBigInt(0).Add(newBigInt(0).Mul(first, newBigInt(40)), second)

			wire = vlqEncodeBig(combined)

			// remaining arcs
			for i := 2; i < len(oid); i++ {
				wire = append(wire, vlqEncodeBig(oid[i].Big())...)
			}
		}

		if err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *oidCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdOIDRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdOIDRead[T any](c *oidCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	var err error
	if tlv.Compound {
		// unwrap ONE explicit layer if present
		if tlv, err = getTLV(pkt, o); err != nil {
			return err
		}
	}

	var wire []byte
	if wire, err = objectIdentifierReadData(pkt, tlv, o); err == nil {

		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out T
			if c.decodeHook != nil {
				out, err = c.decodeHook(wire)
			} else {
				var subs []*big.Int
				for off := 0; off < len(wire) && err == nil; {
					var v *big.Int
					if v, err = readArc(wire, &off); err == nil {
						subs = append(subs, v)
					}
				}

				if len(subs) == 0 {
					err = primitiveErrorf("OBJECT IDENTIFIER is zero")
				} else {
					arcs := objectIdentifierReadExpandFirstArcs(subs)
					out = fromObjectIdentifier[T](arcs)
				}
			}

			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = out
					pkt.AddOffset(tlv.Length)
				}
			}
		}
	}

	return err
}

// VLQ-decode the sub-identifiers
func readArc(buf []byte, p *int) (*big.Int, error) {
	n := newBigInt(0)
	for {
		if *p >= len(buf) {
			return nil, primitiveErrorf("OBJECT IDENTIFIER contains truncated VLQ")
		}
		b := buf[*p]
		*p++
		n.Lsh(n, 7).Or(n, newBigInt(int64(b&0x7F)))
		if b&0x80 == 0 {
			return n, nil
		}
	}
}

func objectIdentifierReadExpandFirstArcs(subs []*big.Int) (arcs []Integer) {
	// Expand the first compressed sub-identifier into arcs 0 & 1
	forty, eighty := newBigInt(40), newBigInt(80)
	var first, second *big.Int
	switch {
	case subs[0].Cmp(forty) < 0:
		first, second = newBigInt(0), subs[0]
	case subs[0].Cmp(eighty) < 0:
		first, second = newBigInt(1), newBigInt(0).Sub(subs[0], forty)
	default:
		first, second = newBigInt(2), newBigInt(0).Sub(subs[0], eighty)
	}

	toInt := func(b *big.Int) Integer {
		if b.IsInt64() {
			return Integer{native: b.Int64()}
		}
		return Integer{big: true, bigInt: b}
	}

	arcs = []Integer{toInt(first), toInt(second)}
	for i := 1; i < len(subs); i++ {
		arcs = append(arcs, toInt(subs[i]))
	}

	return
}

func objectIdentifierReadData(pkt PDU, tlv TLV, o *Options) (data []byte, err error) {
	if len(tlv.Value) != 0 {
		// We were handed some bytes; trust *their* length, not tlv.Length.
		n := len(tlv.Value)
		if tlv.Length > 0 && tlv.Length < n {
			n = tlv.Length // trim any over-read wrapper junk
		}
		data = tlv.Value[:n]
	} else {
		// Value empty: cursor sits on header of the real primitive TLV.
		var child TLV
		if child, err = getTLV(pkt, o); err == nil {
			data = child.Value[:child.Length] // getTLV verified bounds
		}
	}

	if len(data) == 0 {
		err = primitiveErrorf("OBJECT IDENTIFIER content is zero")
	}

	return
}

func RegisterOIDAlias[T any](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint,
	user ...Constraint,
) {
	all := append(ConstraintGroup{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &oidCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
		newWith: func(v any) box {
			return &oidCodec[T]{
				val: valueOf[T](v),
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

type relOIDCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *relOIDCodec[T]) Tag() int          { return c.tag }
func (c *relOIDCodec[T]) IsPrimitive() bool { return true }
func (c *relOIDCodec[T]) String() string    { return "relativeOIDCodec" }
func (c *relOIDCodec[T]) getVal() any       { return c.val }
func (c *relOIDCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func toRelativeOID[T any](v T) RelativeOID   { return *(*RelativeOID)(unsafe.Pointer(&v)) }
func fromRelativeOID[T any](i RelativeOID) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *relOIDCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch {
	case pkt.Type().In(BER, CER, DER):
		err = bcdRelOIDRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdRelOIDRead[T any](c *relOIDCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	var err error
	if tlv.Compound {
		if tlv, err = getTLV(pkt, o); err != nil {
			return err
		}
	}

	var wire []byte
	if len(tlv.Value) != 0 {
		n := len(tlv.Value)
		if tlv.Length > 0 && tlv.Length < n {
			n = tlv.Length
		}
		wire = tlv.Value[:n]
	} else {
		var child TLV
		if child, err = getTLV(pkt, o); err == nil {
			wire = child.Value[:child.Length]
		}
	}

	if len(wire) == 0 {
		return primitiveErrorf("RELATIVE-OID decoded empty content")
	}

	decodeVerify := func() (err error) {
		for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
			err = c.decodeVerify[i](wire)
		}

		return
	}

	if err = decodeVerify(); err == nil {
		var out T
		if c.decodeHook != nil {
			out, err = c.decodeHook(wire)
		} else {
			var roid RelativeOID
			if roid, err = relativeOIDReadArcs(wire); err == nil {
				out = fromRelativeOID[T](roid)
			}
		}

		if err == nil {
			cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
			if err = cc(out); err == nil {
				c.val = out
			}
		}
	}

	return err
}

func relativeOIDReadArcs(data []byte) (roid RelativeOID, err error) {
	var (
		i             int
		subidentifier = newBigInt(0)
	)

	for i < len(data) {
		for {
			subidentifier.Lsh(subidentifier, 7)
			subidentifier.Add(subidentifier, newBigInt(int64(data[i]&0x7F)))
			if data[i]&0x80 == 0 {
				break
			}
			i++
			if i >= len(data) {
				err = primitiveErrorf("RELATIVE-OID read truncated subidentifier")
				return
			}
		}
		i++

		var arc Integer
		if subidentifier.IsInt64() {
			arc = Integer{native: subidentifier.Int64()}
		} else {
			arc = Integer{big: true, bigInt: newBigInt(0).Set(subidentifier)}
		}

		roid = append(roid, arc)
		subidentifier = newBigInt(0)
	}

	if len(roid) == 0 {
		err = errorMinRelOIDArcs
	}

	return
}

func (c *relOIDCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch {
	case pkt.Type().In(BER, CER, DER):
		n, err = bcdRelOIDWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdRelOIDWrite[T any](c *relOIDCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			roid := toRelativeOID[T](c.val)
			if len(roid) == 0 {
				return 0, errorMinRelOIDArcs
			}

			for _, arc := range roid {
				if arc.Big().Sign() < 0 {
					return 0, primitiveErrorf("RELATIVE-OID arcs may not be negative")
				}
				wire = append(wire, vlqEncodeBig(arc.Big())...)
			}
		}

		if err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func RegisterRelativeOIDAlias[T any](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint,
	user ...Constraint,
) {
	all := append(ConstraintGroup{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &relOIDCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
		newWith: func(v any) box {
			return &relOIDCodec[T]{
				val: valueOf[T](v),
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterOIDAlias[ObjectIdentifier](TagOID,
		ObjectIdentifierConstraintPhase,
		nil, nil, nil, nil)
	RegisterRelativeOIDAlias[RelativeOID](TagRelativeOID,
		RelativeOIDConstraintPhase,
		nil, nil, nil, nil)
}
