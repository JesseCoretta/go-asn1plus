package asn1plus

/*
real.go contains all types and methods pertaining to the ASN.1
REAL type.
*/

import (
	"math"
	"math/big"
	"reflect"
	"unsafe"
)

/*
RealSpecial implements a [Real] flag to denote a special
value or state, such as [RealPlusInfinity].
*/
type RealSpecial int

const (
	RealNormal        RealSpecial = 0  // normal
	RealPlusInfinity  RealSpecial = 1  // +∞
	RealMinusInfinity RealSpecial = -1 // –∞
)

/*
String returns the string representation of the receiver instance.
*/
func (r RealSpecial) String() string {
	var s string
	switch r {
	case RealPlusInfinity:
		s = `PLUS-INFINITY`
	case RealMinusInfinity:
		s = `MINUS-INFINITY`
	}

	return s
}

/*
Real implements the ASN.1 REAL type (tag 9).
*/
type Real struct {
	// If non-zero, all other fields are ignored.
	Special RealSpecial

	// If Special == RealNormal, then the REAL’s value will be Mantissa × Base^Exponent
	Mantissa Integer // The integer m; may be negative
	Base     int     // The base (typically 2, 8, 10 or 16)
	Exponent int     // The exponent
}

/*
RealConstraintPhase declares the appropriate phase for the
constraining of values during codec operations. See the
[CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var RealConstraintPhase = CodecConstraintDecoding

/*
NewRealPlusInfinity returns an instance of [Real] which represents positive infinity (∞).
*/
func NewRealPlusInfinity() Real {
	return Real{Special: RealPlusInfinity}
}

/*
NewRealPlusInfinity returns an instance of [Real] which represents negative infinity (-∞).
*/
func NewRealMinusInfinity() Real {
	return Real{Special: RealMinusInfinity}
}

/*
NewReal returns an instance of [Real] alongside an error following an attempt
to marshal a (non-infinity) mantissa, base and exponent combination.

When creating an instance of [Real] that describes a positive or negative infinity,
use [NewRealPlusInfinity] and [NewRealMinusInfinity] instead of this function.

Only base values of 2, 8, 10 and 16 are currently supported.
*/
func NewReal(mantissa any, base, exponent int, constraints ...Constraint) (Real, error) {
	var (
		_r,
		r Real
		i   Integer
		err error
	)

	if i, err = NewInteger(mantissa); err == nil {
		_r = Real{
			Mantissa: i,
			Base:     base,
			Exponent: exponent,
		}
	}

	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_r)
	}

	if err == nil {
		r = _r
	}

	return r, err
}

/*
Big returns the *[big.Float] representation of the receiver instance.
*/
func (r Real) Big() *big.Float {
	switch r.Special {
	case RealPlusInfinity, RealMinusInfinity:
		// Convert IEEE +/- infinity to a *big.Float.
		return new(big.Float).SetFloat64(math.Inf(int(r.Special)))
	}

	// Compute Mantissa × Base^Exponent. Convert the
	// mantissa from *big.Int to *big.Float.
	result := new(big.Float).SetInt(r.Mantissa.Big())

	// We now want to compute factor := Base^Exponent.
	// Because Exponent may be negative, we will first
	// compute with the absolute value...
	absExp := r.Exponent
	if absExp < 0 {
		absExp = -absExp
	}
	baseInt := big.NewInt(int64(r.Base))
	// Compute baseInt^(|Exponent|) exactly as a big.Int.
	powerInt := new(big.Int).Exp(baseInt, big.NewInt(int64(absExp)), nil)
	// Convert that integer factor to a big.Float.
	factor := new(big.Float).SetInt(powerInt)

	// If the original exponent is negative, take the reciprocal.
	if r.Exponent < 0 {
		one := big.NewFloat(1)
		factor.Quo(one, factor)
	}

	// Multiply the mantissa by the computed factor.
	result.Mul(result, factor)

	return result
}

/*
Float64 returns the numeric value of r as a float64. If r encodes ±∞,
the corresponding math.Inf value is returned. If the magnitude cannot
be represented (overflow/underflow) the result follows IEEE-754: ±Inf
or 0, respectively.
*/
func (r Real) Float() float64 {
	switch r.Special {
	case RealPlusInfinity:
		return math.Inf(+1)
	case RealMinusInfinity:
		return math.Inf(-1)
	}

	// Mantissa -> float64.
	//  big.Int has no direct Float64 method, so use big.Float as a thin
	//  wrapper *only* for the conversion, we immediately discard it.
	mant64, _ := new(big.Float).SetInt(r.Mantissa.Big()).Float64()

	// Base^Exponent as float64.
	base64 := float64(r.Base)
	exp64 := float64(r.Exponent)

	// let over/underflow be handled by math.Pow
	factor := math.Pow(base64, exp64)

	return mant64 * factor
}

/*
String returns the string representation of the receiver instance.
*/
func (r Real) String() string {
	if r.Special != RealNormal {
		return r.Special.String()
	}

	bld := newStrBuilder()
	bld.WriteString("{mantissa ")
	bld.WriteString(r.Mantissa.String())
	bld.WriteString(", base ")
	bld.WriteString(itoa(r.Base))
	bld.WriteString(", exponent ")
	bld.WriteString(itoa(r.Exponent))
	bld.WriteString("}")

	return bld.String()
}

/*
Tag returns the integer constant [TagReal].
*/
func (r Real) Tag() int { return TagReal }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r Real) IsPrimitive() bool { return true }

/*
encodeRealExponent returns an instance of []byte, containing the
encoding of an exponent (int) using the minimal two's complement
representation.
*/
func encodeRealExponent(exp int) []byte {
	// Use minimal two's complement representation.
	if exp == 0 {
		return []byte{0x00}
	}
	negative := exp < 0
	absVal := exp
	if negative {
		absVal = -exp
	}
	var buf []byte
	for absVal > 0 {
		buf = append([]byte{byte(absVal & 0xFF)}, buf...)
		absVal >>= 8
	}
	// Ensure proper two's complement representation.
	var bflag byte = 0x00
	if negative {
		carry := byte(1)
		for i := len(buf) - 1; i >= 0; i-- {
			buf[i] = ^buf[i] + carry
			if buf[i] != 0 {
				carry = 0
			}
		}
		bflag = 0xFF
	}
	// Prepend 0x00 or 0xFF (if negative) if the sign bit is not set.
	if buf[0]&0x80 == 0 {
		buf = append([]byte{bflag}, buf...)
	}
	return buf
}

/*
decodeRealExponent returns an int, representing the decoded
two's complement big-endian integer from the input expBytes.
*/
func decodeRealExponent(expBytes []byte) int {
	n := 0
	for _, b := range expBytes {
		n = (n << 8) | int(b)
	}
	if len(expBytes) > 0 && expBytes[0]&0x80 != 0 {
		n -= 1 << (8 * len(expBytes))
	}
	return n
}

/*
decodeMantissa decodes the mantissa bytes (a big-endian
unsigned integer) into a *big.Int.
*/
func decodeMantissa(mBytes []byte) *big.Int {
	return newBigInt(0).SetBytes(mBytes)
}

func encodeMantissa(b *big.Int) []byte {
	bBytes := b.Bytes()
	if len(bBytes) == 0 {
		return []byte{0}
	}
	return bBytes
}

func validRealBase(base int) bool {
	return base == 2 || base == 8 || base == 10 || base == 16
}

// float64Components decomposes f into mantissa × base^exp.
// base must be 2, 8, 10 or 16.
//
//   - mantissa is an *odd* integer for base 2/8 (not divisible by base).
//     For base 10 it is stripped of trailing zeros.
//   - sign is carried in mantissa (negative mantissa ⇒ negative number).
//   - Special values:
//     ±Inf  → mant=±1 , exp=math.MaxInt32
//     0     → mant=0  , exp=0
//     NaN   → mant=0  , exp=math.MinInt32
func float64Components(f float64, base int) (mant *big.Int, exp int, err error) {
	if !validRealBase(base) {
		return nil, 0, primitiveErrorf("REAL: unsupported base ", base)
	}

	switch {
	case math.IsInf(f, +1):
		return newBigInt(+1), math.MaxInt32, nil
	case math.IsInf(f, -1):
		return newBigInt(-1), math.MaxInt32, nil
	case math.IsNaN(f):
		return newBigInt(0), math.MinInt32, nil
	case f == 0:
		return newBigInt(0), 0, nil
	}

	neg := math.Signbit(f)
	if neg {
		f = -f
	}

	switch base {
	case 2, 8:
		mant, exp = float64Base2or8Components(f, base)

	case 10:
		// Re-use strconv to get *decimal* scientific notation.
		// fmt:  d.dddde±xx   (exact, shortest)
		sci := fmtFloat(f, 'e', -1, 64)

		// split "d.dddd" and "e±xx"
		parts := split(sci, "e")
		mantStr := replaceAll(parts[0], ".", "")
		exp10, _ := atoi(parts[1])
		exp10 -= len(mantStr) - 1

		mant = newBigInt(0)
		mant, _ = mant.SetString(mantStr, 10)
		exp = exp10
	case 16:
		// reuse the base-2 extractor.
		m2, e2 := float64Base2or8Components(f, 2)

		// 16^k == 2^(4k).  Split the binary exponent into a
		// multiple-of-4 part (goes into exp16) and a remainder
		// 0..3 bits (folded into the mantissa).
		exp16 := e2 / 4
		rem := e2 % 4
		if rem < 0 {
			rem += 4 // make remainder positive
			exp16--  // and compensate exponent
		}

		// Shift mantissa left by the remaining 0…3 bits.
		if rem != 0 {
			m2 = new(big.Int).Lsh(m2, uint(rem))
		}

		mant, exp = m2, exp16
	}

	if neg {
		mant.Neg(mant)
	}

	return mant, exp, nil
}

func float64Base2or8Components(f float64, base int) (mant *big.Int, exp int) {
	frac, e2 := math.Frexp(f) // f = frac · 2^e2,  ½ ≤ frac < 1
	const sigBits = 53
	m := big.NewInt(int64(frac * (1 << sigBits)))
	e2 -= sigBits // we pulled the fraction up by 2^53

	if base == 8 {
		q, r := e2/3, e2%3 // r may be negative
		if r < 0 {         // canonicalise so 0 ≤ r ≤ 2
			q--
			r += 3 // now r ∈ {1,2,3}
		}
		exp = q
		if r != 0 {
			m.Lsh(m, uint(r)) // shift count is ALWAYS positive
		}
	} else { // base == 2
		exp = e2
	}

	if base == 2 {
		tz := m.TrailingZeroBits()
		if tz > 0 {
			m.Rsh(m, tz)
			exp += int(tz)
		}
	} else {
		b8 := big.NewInt(8)
		for new(big.Int).Mod(m, b8).Sign() == 0 {
			m.Div(m, b8)
			exp++
		}
	}
	mant = m

	return
}

// float64 -> mantissa + exponent
func float64ToRealParts(f float64, base int) (any, int, error) {
	mant, exp, err := float64Components(f, base)
	return mant, exp, err
}

// *big.Float -> mantissa + exponent
func bigFloatToRealParts(bf *big.Float, base int) (any, int, error) {
	f64, _ := bf.Float64()
	mant, exp, err := float64Components(f64, base)
	return mant, exp, err
}

func toReal[T any](v T) Real   { return *(*Real)(unsafe.Pointer(&v)) }
func fromReal[T any](r Real) T { return *(*T)(unsafe.Pointer(&r)) }

type realCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *realCodec[T]) Tag() int          { return c.tag }
func (c *realCodec[T]) IsPrimitive() bool { return true }
func (c *realCodec[T]) String() string    { return "realCodec" }
func (c *realCodec[T]) getVal() any       { return c.val }
func (c *realCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func (c *realCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdRealWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdRealWrite[T any](c *realCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err := cc(c.val); err == nil {
		r := toReal(c.val)
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			var ok bool
			if wire, ok = infinityToByte(r.Special); !ok {
				if r.Mantissa.Big().Sign() == 0 {
					// zero: empty content
					wire = nil
				} else {
					// normal number
					signFlag := byte(0)
					if r.Mantissa.Big().Sign() < 0 {
						signFlag = 0x20
					}

					baseIndicator := realBaseToHeader(r.Base)
					expBytes := encodeRealExponent(r.Exponent)
					if len(expBytes) > 15 {
						return 0, primitiveErrorf("REAL: exponent too long")
					}
					header := 0x80 | baseIndicator | signFlag | byte(len(expBytes))
					mantissaBytes := encodeMantissa(r.Mantissa.Big().Abs(r.Mantissa.Big()))

					wire = append([]byte{header}, expBytes...)
					wire = append(wire, mantissaBytes...)
				}
			}
		}

		tag, cls := effectiveHeader(c.tag, 0, o)
		start := pkt.Offset()
		if err == nil {
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *realCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdRealRead[T](c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdRealRead[T any](c *realCodec[T], pkt PDU, tlv TLV, o *Options) (err error) {
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
			var out T
			if c.decodeHook != nil {
				out, err = c.decodeHook(wire)
			} else {
				var r Real
				switch len(wire) {
				case 0: // zero
					zero, _ := NewInteger(0)
					r = Real{Mantissa: zero, Base: 2, Exponent: 0}
				case 1: // ±∞
					if r, err = byteToInfinity(wire[0]); err != nil {
						return
					}
				default:
					header := wire[0]
					expLen := int(header & 0x0F)
					if 1+expLen >= len(wire) {
						return primitiveErrorf("REAL: insufficient data for exponent")
					}

					exp := decodeRealExponent(wire[1 : 1+expLen])
					mantissa := decodeMantissa(wire[1+expLen:])

					if header&cmpndByte != 0 {
						mantissa.Neg(mantissa)
					}

					intMant, _ := NewInteger(mantissa)
					r = Real{
						Mantissa: intMant,
						Base:     realHeaderToBase(header), // 2, 8, 10 or 16
						Exponent: exp,
					}
				}

				out = fromReal[T](r)
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

func byteToInfinity(b byte) (r Real, err error) {
	switch b {
	case plusIByte:
		r = NewRealPlusInfinity()
	case minusIByte:
		r = NewRealMinusInfinity()
	default:
		err = primitiveErrorf("REAL: invalid special value for INFINITY")
	}

	return
}

func infinityToByte(special RealSpecial) (b []byte, ok bool) {
	switch special {
	case RealPlusInfinity:
		b = []byte{plusIByte}
	case RealMinusInfinity:
		b = []byte{minusIByte}
	}

	ok = len(b) == 1

	return
}

func realHeaderToBase(header byte) (base int) {
	switch (header & 0xC0) >> 6 {
	case 3:
		base = 10
	case 2:
		base = 16
	case 1:
		base = 8
	default:
		base = 2
	}

	return
}

func realBaseToHeader(base int) (header byte) {
	switch base {
	case 10:
		header = 0xC0
	case 16:
		header = 0x80
	case 8:
		header = 0x40
	default:
		header = 0x00 // 2
	}

	return
}

func RegisterRealAlias[T any](
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
			return &realCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
		newWith: func(v any) box {
			return &realCodec[T]{
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
	RegisterRealAlias[Real](TagReal,
		RealConstraintPhase,
		nil, nil, nil, nil)
}
