package asn1plus

/*
int.go contains all types and methods pertaining to the ASN.1
INTEGER type.
*/

import (
	"math"
	"math/big"
	"reflect"
	"unsafe"
)

/*
Integer implements the unbounded ASN.1 INTEGER type (tag 2). Note
that *[big.Int] is used internally ONLY if the number overflows int64.

A zero instance of this type equates to int64(0).
*/
type Integer struct {
	big    bool
	native int64    // Stores native integer values when possible
	bigInt *big.Int // Stores big.Int values only when necessary
}

/*
IntegerConstraintPhase declares the appropriate phase for
the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var IntegerConstraintPhase = CodecConstraintDecoding

/*
NewInteger returns an instance of [Integer] alongside an error
following an attempt to marshal x as an ASN.1 INTEGER.

Input types may be int, int32, int64, uint64, string, []byte or
*[math/big.Int]. In the case of []byte, the value is expected to
be the Big Endian representation of the desired integer.

Any signed magnitude is permitted. Effective integers which overflow
int64 are stored as *[big.Int].

When the input value is NOT a string and when NO constraints are
utilized, it is safe to shadow the return error.

See also [MustNewInteger].
*/
func NewInteger[T any](x T, constraints ...Constraint) (i Integer, err error) {
	if i, err = assertInteger(x); err == nil {
		if len(constraints) > 0 {
			err = ConstraintGroup(constraints).Constrain(i)
		}
	}

	return
}

/*
MustNewInteger returns an instance of [Integer] and panics if [NewInteger]
returned an error during processing of x.
*/
func MustNewInteger[T any](x T, constraints ...Constraint) Integer {
	i, err := NewInteger(x, constraints...)
	if err != nil {
		panic(err)
	}
	return i
}

func assertInteger[T any](v T) (i Integer, err error) {
	switch value := any(v).(type) {
	case int:
		i = Integer{native: int64(value)}
	case int64:
		i = Integer{native: value}
	case uint64:
		i = uint64ToInteger(value)
	case []byte:
		i = bEToInteger(value)
	case *big.Int:
		i = bigToInteger(value)
	case int32:
		i = Integer{native: int64(value)}
	case string:
		i, err = strToInteger(value)
	case Integer:
		i = value
	default:
		err = errorBadTypeForConstructor("INTEGER", value)
	}
	return
}

/*
Tag returns the integer constant [TagInteger].
*/
func (_ Integer) Tag() int { return TagInteger }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (_ Integer) IsPrimitive() bool { return true }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r Integer) IsZero() bool { return &r == nil }

/*
String returns the string representation of the receiver instance.
*/
func (r Integer) String() string {
	var s string
	if r.big {
		s = r.bigInt.String()
	} else {
		s = fmtInt(r.native, 10)
	}

	return s
}

/*
IsBig returns a Boolean value indicative of the underlying value
overflowing int64.
*/
func (r Integer) IsBig() bool { return r.big }

/*
Native returns the underlying int64 value found within the receiver
instance. Note that this method should not be used unless a call of
[Integer.IsBig] beforehand returns false.
*/
func (r Integer) Native() int64 { return r.native }

/*
Big returns the *[big.Int] form of the receiver instance.

Note that use of this method constructs an entirely new instance of
*[big.Int] if the underlying value is an int64.  Thus, this method
should only usually be needed if a call to [Integer.IsBig] returns
true. In that case, the preexisting *[big.Int] value is returned, as
opposed to being generated on the fly.

When [Integer.IsBig] returns false, the return instance of *[big.Int]
is entirely independent of the receiver and does not replace the
underlying value. This can be useful, though potentially costly, in
cases where methods extended by *[big.Int] that are not wrapped in
this package directly need to be accessed for some reason.
*/
func (r Integer) Big() (i *big.Int) {
	if r.big {
		i = r.bigInt
	} else {
		i = newBigInt(r.native)
	}

	return
}

/*
Bytes returns the receiver instance expressed as Big Endian bytes.
*/
func (r Integer) Bytes() []byte {
	var buf []byte
	if r.big {
		buf = r.bigInt.Bytes()
	} else {
		buf = int64ToBE(r.native)
	}

	return buf
}

/*
Eq returns a bool indicative of an equality match between the
receiver instance and x.
*/
func (r Integer) Eq(x any) bool { return r.cmpAny(x) == 0 }

/*
Ne returns a bool indicative of a negative equality match between
the receiver instance and x.
*/
func (r Integer) Ne(x any) bool { return r.cmpAny(x) != 0 }

/*
Gt returns a bool indicative of r being greater than x.
*/
func (r Integer) Gt(x any) bool { return r.cmpAny(x) > 0 }

/*
Ge returns a bool indicative of r being greater than or equal to x.
*/
func (r Integer) Ge(x any) bool { return r.cmpAny(x) >= 0 }

/*
Lt returns a bool indicative of r being less than x.
*/
func (r Integer) Lt(x any) bool { return r.cmpAny(x) < 0 }

/*
Le returns a bool indicative of r being less than or equal to x.
*/
func (r Integer) Le(x any) bool { return r.cmpAny(x) <= 0 }

func (r Integer) cmpAny(x any) (result int) {
	switch t := x.(type) {
	case Integer:
		result = cmpInteger(r, t)

	case int:
		result = r.cmpInt64(int64(t))

	case int32:
		result = r.cmpInt64(int64(t))

	case int64:
		result = r.cmpInt64(t)

	case uint64:
		result = r.cmpUint64(t)

	case []byte:
		result = cmpInteger(r, bEToInteger(t))

	case *big.Int:
		result = r.cmpBig(t)

	default:
		panic(primitiveErrorf("INTEGER: unsupported type for comparison ", refTypeOf(x)))
	}

	return
}

func cmpInteger(a, b Integer) int {
	if !a.big && !b.big {
		switch {
		case a.native < b.native:
			return -1
		case a.native > b.native:
			return +1
		default:
			return 0
		}
	}
	return a.Big().Cmp(b.Big())
}

func (r Integer) cmpInt64(v int64) int {
	if !r.big {
		switch {
		case r.native < v:
			return -1
		case r.native > v:
			return +1
		default:
			return 0
		}
	}
	return r.Big().Cmp(big.NewInt(v))
}

func (r Integer) cmpUint64(u uint64) int {
	if !r.big && u <= math.MaxInt64 {
		return r.cmpInt64(int64(u))
	}
	b := newBigInt(0).SetUint64(u)
	return r.Big().Cmp(b)
}

func (r Integer) cmpBig(b *big.Int) int {
	if !r.big {
		return big.NewInt(r.native).Cmp(b)
	}
	return r.bigInt.Cmp(b)
}

func bEToInt64(b []byte) int64 {
	n := len(b)
	if n > 8 {
		panic("bigEndianToInt64: buffer length must be ≤ 8")
	}

	pad := zeroByte
	if n > 0 && b[0]&0x80 != 0 {
		pad = 0xFF
	}

	var u uint64
	for i := 0; i < 8-n; i++ {
		u = (u << 8) | uint64(pad)
	}
	for _, by := range b {
		u = (u << 8) | uint64(by)
	}
	return int64(u)
}

func int64ToBE(n int64) []byte {
	b := make([]byte, 8)
	u := uint64(n)
	for i := 7; i >= 0; i-- {
		b[i] = byte(u & 0xFF)
		u >>= 8
	}
	return b
}

func bEFitsInt64(b []byte) bool {
	n := len(b)
	if n <= 8 {
		return true
	}
	high := b[n-8]
	var ext byte = zeroByte
	if high&0x80 != 0 {
		ext = 0xFF
	}
	for i := 0; i < n-8; i++ {
		if b[i] != ext {
			return false
		}
	}
	return true
}

func bEToInteger(b []byte) (i Integer) {
	if i.big = !bEFitsInt64(b); i.big {
		i.bigInt = newBigInt(0).SetBytes(b)
	} else {
		i.native = bEToInt64(b)
	}

	return
}

func strToInteger(num string) (i Integer, err error) {
	if _i, ok := newBigInt(0).SetString(num, 10); !ok {
		err = primitiveErrorf("INTEGER: invalid string value ", num)
	} else if _i.IsInt64() {
		i = Integer{native: _i.Int64()}
	} else {
		i = Integer{big: true, bigInt: _i}
	}

	return
}

func bigToInteger(num *big.Int) (i Integer) {
	if i.big = !num.IsInt64(); i.big {
		i.bigInt = num
	} else {
		i.native = num.Int64()
	}

	return
}

func uint64ToInteger(num uint64) (i Integer) {
	if i.big = num > uint64(math.MaxInt64); i.big {
		i.bigInt = newBigInt(0).SetUint64(num)
	} else {
		i.native = int64(num)
	}

	return
}

func decodeIntegerContent(encoded []byte) (val *big.Int) {
	val = newBigInt(0)
	val.SetBytes(encoded)
	if len(encoded) > 0 && encoded[0]&0x80 != 0 {
		// Compute 2^(len(encoded)*8) and subtract it.
		bitLen := uint(len(encoded) * 8)
		twoPow := newBigInt(0).Lsh(newBigInt(1), bitLen)
		val.Sub(val, twoPow)
	}

	return
}

func encodeIntegerContent(i *big.Int) (data []byte) {
	if i.Sign() >= 0 {
		// For zero and positive integers, use the big-endian minimal encoding.
		b := i.Bytes()
		if len(b) == 0 {
			// Special case: 0 is encoded as a single 0x00 byte.
			b = []byte{zeroByte}
		}
		// If the MSB of the first byte is 1, prepend a 0x00 byte to indicate positive.
		if b[0]&0x80 != 0 {
			b = append([]byte{zeroByte}, b...)
		}
		data = b
	} else {
		// For negative integers, we calculate the minimal two's complement representation.
		// First, determine the minimum number of octets n needed.
		abs := newBigInt(0).Abs(i)
		n := (abs.BitLen() + 7) / 8

		// For negative numbers, n must be chosen so that i >= - (1 << (8*n - 1)).
		min := newBigInt(0).Lsh(newBigInt(1), uint(8*n-1))
		min.Neg(min)
		if i.Cmp(min) < 0 {
			n++ // increase length if i is too small for n octets.
		}
		// Compute 2^(8*n) and add i (note: i is negative), giving the two's complement.
		mod := newBigInt(0).Lsh(newBigInt(1), uint(8*n))
		value := newBigInt(0).Add(mod, i)
		b := value.Bytes()
		data = b
	}

	return
}

/*
encodeNativeInt returns the minimal two's complement encoding for an int value.
*/
func encodeNativeInt(value int) []byte {
	// If the value is zero, return single zero.
	if value == 0 {
		return []byte{zeroByte}
	}

	v := int64(value)
	negative := value < 0
	var raw []byte

	// Loop until we have reached a state where further bytes would be redundant.
	for {
		b := byte(v & 0xff)
		// Prepend the computed byte.
		raw = append([]byte{b}, raw...)
		// Shift v right arithmetically.
		v >>= 8

		// For positive numbers: stop if remaining v is 0 and the top bit of b is 0.
		// For negative numbers: stop if remaining v is -1 and the top bit of b is 1.
		if !negative {
			if v == 0 && (b&0x80) == 0 {
				break
			}
		} else {
			if v == -1 && (b&0x80) == 0x80 {
				break
			}
		}
	}

	return raw
}

/*
decodeNativeInt takes a BER/DER INTEGER encoding (a byte slice) and returns the
corresponding int value. It assumes the encoded integer fits in an int, which
is safe since this fact is confirmed prior to any call of this function.
*/
func decodeNativeInt(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, primitiveErrorf("INTEGER: zero bytes for decoding")
	}

	// Interpret the value in two's complement.
	// Determine if the number is negative from the first byte.
	negative := data[0]&indefByte != 0

	var value int64 = 0
	for _, b := range data {
		value = (value << 8) | int64(b)
	}

	// If negative and the number of bits is less than 64,
	// then sign-extend the result.
	nBits := len(data) * 8
	if negative && nBits < 64 {
		// Shift left then arithmetic right to sign-extend.
		shift := 64 - nBits
		value = (value << shift) >> shift
	}

	return int(value), nil
}

type integerCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func toInt[T any](v T) Integer   { return *(*Integer)(unsafe.Pointer(&v)) }
func fromInt[T any](i Integer) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *integerCodec[T]) Tag() int          { return c.tag }
func (c *integerCodec[T]) IsPrimitive() bool { return true }
func (c *integerCodec[T]) String() string    { return "IntCodec" }
func (c *integerCodec[T]) getVal() any       { return c.val }
func (c *integerCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

// NOTE: called for both Integer and Enumerated
func (c *integerCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdIntegerWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdIntegerWrite[T any](c *integerCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	intVal := toInt(c.val)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(intVal); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			var bi *big.Int
			if intVal.big {
				bi = intVal.bigInt
			} else {
				bi = newBigInt(intVal.native)
			}
			wire = encodeIntegerContent(bi)
		}

		if err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			err = writeTLV(pkt, tlv, o)
			if err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

// NOTE: called for both Integer and Enumerated
func (c *integerCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdIntegerRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdIntegerRead[T any](c *integerCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {

		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out Integer
			if c.decodeHook != nil {
				var t T
				t, err = c.decodeHook(wire)
				out = toInt(t)
			} else {
				bi := decodeIntegerContent(wire)
				if bi.IsInt64() {
					out = Integer{native: bi.Int64()}
				} else {
					out = Integer{big: true, bigInt: bi}
				}
			}

			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = fromInt[T](out)
					pkt.AddOffset(tlv.Length)
				}
			}
		}
	}

	return err
}

func RegisterIntegerAlias[T any](
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
			return &integerCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
		newWith: func(v any) box {
			return &integerCodec[T]{val: valueOf[T](v),
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterIntegerAlias[Integer](TagInteger,
		IntegerConstraintPhase,
		nil, nil, nil, nil)
}
