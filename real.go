package asn1plus

/*
real.go contains all types and methods pertaining to the ASN.1
REAL type.
*/

import (
	"math"
	"math/big"
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
	Mantissa Integer // The integer m; may be negative; use a *big.Int for arbitrary precision
	Base     int     // The base (typically 2 or 10)
	Exponent int     // The exponent
}

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
use [NewRealPlusInfinity] and [NewRealMinusInfinity] instead.
*/
func NewReal(mantissa any, base, exponent int, constraints ...Constraint[Real]) (Real, error) {
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
		var group ConstraintGroup[Real] = constraints
		err = group.Validate(_r)
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

func (r Real) write(pkt Packet, opts Options) (n int, err error) {
	switch pkt.Type() {
	case BER, DER:
		n, err = r.writeBER(pkt, opts)

	default:
		err = mkerr("Unsupported packet type for REAL encoding")
	}

	return
}

func (r *Real) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)

	default:
		err = mkerr("Unsupported packet type for REAL decoding")
	}

	return
}

func (r *Real) writeBER(pkt Packet, opts Options) (n int, err error) {
	// Handle special REAL values first.
	if r.Special != RealNormal {
		if r.Special == RealPlusInfinity {
			pkt.Append([]byte{byte(r.Tag()), 1, 0x40}...)
			pkt.SetOffset(pkt.Len())
			return pkt.Len(), nil
		} else if r.Special == RealMinusInfinity {
			pkt.Append([]byte{byte(r.Tag()), 1, 0x41}...)
			pkt.SetOffset(pkt.Len())
			return pkt.Len(), nil
		}
	}

	// ZERO is encoded with zero content length.
	if r.Mantissa.Big().Sign() == 0 {
		pkt.Append([]byte{byte(r.Tag()), 0}...)
		pkt.SetOffset(2)
		return 2, nil
	}

	// Determine sign.
	var signFlag byte = 0
	if r.Mantissa.Big().Sign() < 0 {
		signFlag = 0x20
	}

	// Set the base indicator:
	// For our purposes, use base 2 if r.Base is not 10 or 16.
	// TODO: revisit this.
	var baseIndicator byte
	switch r.Base {
	case 10:
		baseIndicator = 0xC0 // bits 7-6 = 11 => base 10
	case 16:
		baseIndicator = 0x80 // bits 7-6 = 10 => base 16
	default:
		baseIndicator = 0x00 // base 2 (bits 7-6 = 00)
	}

	// Use scaling factor 0.
	var scale byte = 0

	// Encode the exponent.
	expBytes := encodeRealExponent(r.Exponent)
	expLen := len(expBytes)
	if expLen > 15 {
		return 0, mkerr("Exponent too long")
	}
	// Build the header octet:
	// Bit 8 is set (0x80), then OR with baseIndicator, signFlag,
	//(scale<<4) and exponent length (lower 4 bits).
	header := byte(0x80) | baseIndicator | signFlag | (scale << 4) | byte(expLen)

	// Encode the mantissa.
	// Use absolute value for mantissa encoding.
	mantissaBytes := encodeMantissa(r.Mantissa.Big().Abs(r.Mantissa.Big()))
	content := append([]byte{header}, expBytes...)
	content = append(content, mantissaBytes...)
	if len(content) >= 128 {
		return 0, mkerr("REAL content too long")
	}

	off := pkt.Offset()
	if err = writeTLV(pkt, pkt.Type().newTLV(0, r.Tag(), len(content), false, content...), opts); err == nil {
		n = pkt.Offset() - off
	}

	return
}

func (r *Real) readBER(pkt Packet, tlv TLV, opts Options) error {
	var data []byte
	var err error
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err != nil {
		return err
	}
	if pkt.Offset()+tlv.Length > pkt.Len() {
		return errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
	}
	pkt.SetOffset(pkt.Offset() + tlv.Length)

	// Handle special cases.
	if len(data) == 0 {
		zeroInt, _ := NewInteger(0)
		*r = Real{Special: RealNormal, Mantissa: zeroInt, Base: 2, Exponent: 0}
		return nil
	}
	if len(data) == 1 {
		if data[0] == 0x40 {
			*r = NewRealPlusInfinity()
			return nil
		} else if data[0] == 0x41 {
			*r = NewRealMinusInfinity()
			return nil
		}
	}

	// The writer encoded REAL content as:
	// Byte0: header, where:
	//   Bits 7-6: base indicator
	//   Bits 5-4: scaling factor
	//   Bit 5 (0x20) is also used as the sign flag (1 if negative)
	//   Bits 3-0: exponent length (L)
	// Bytes1..L: exponent bytes (in two's complement, big-endian)
	// Remaining bytes: mantissa bytes
	header := data[0]
	expLen := int(header & 0x0F)          // lower 4 bits: exponent length
	scale := int((header & 0x30) >> 4)    // bits 5-4: scaling factor
	sign := int((header & 0x20) >> 5)     // bit 5: sign flag (1 => negative)
	baseCode := int((header & 0xC0) >> 6) // bits 7-6: base indicator

	if len(data) < 1+expLen {
		return mkerr("Insufficient data for REAL exponent")
	}
	expBytes := data[1 : 1+expLen]
	exponent := 0
	for _, b := range expBytes {
		exponent = (exponent << 8) | int(b)
	}
	if expLen > 0 && expBytes[0]&0x80 != 0 {
		exponent -= 1 << (8 * expLen)
	}
	// Adjust exponent by subtracting the scaling factor.
	exponent -= scale

	if len(data) < 1+expLen+1 {
		return mkerr("Missing mantissa bytes")
	}
	mantissaBytes := data[1+expLen:]
	mantissaBig := decodeMantissa(mantissaBytes)
	if sign != 0 {
		mantissaBig.Neg(mantissaBig)
	}
	intVal, _ := NewInteger(mantissaBig)

	// Determine base from baseCode.
	// TODO: revisit this.
	var realBase int
	switch baseCode {
	case 3:
		realBase = 10
	case 2:
		realBase = 16
	default:
		realBase = 2
	}

	*r = Real{
		Special:  RealNormal,
		Mantissa: intVal,
		Base:     realBase,
		Exponent: exponent,
	}
	return nil
}

func realBaseSwitch(baseCode byte) (base int, err error) {
	switch baseCode {
	case 0:
		base = 2
	case 1:
		base = 8
	case 2:
		base = 16
	case 3:
		base = 10
	default:
		err = mkerr("Unsupported base encoding in REAL")
	}

	return
}

func encodeMantissa(b *big.Int) []byte {
	bBytes := b.Bytes()
	if len(bBytes) == 0 {
		return []byte{0}
	}
	return bBytes
}

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
	if negative {
		carry := byte(1)
		for i := len(buf) - 1; i >= 0; i-- {
			buf[i] = ^buf[i] + carry
			if buf[i] != 0 {
				carry = 0
			}
		}
		// Prepend 0xFF if the sign bit is not set.
		if buf[0]&0x80 == 0 {
			buf = append([]byte{0xFF}, buf...)
		}
	} else {
		// Prepend 0x00 if the sign bit is set.
		if buf[0]&0x80 != 0 {
			buf = append([]byte{0x00}, buf...)
		}
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

// float64Components decomposes f into mantissa × base^exp.
// base must be 2, 8 or 10.
//
//   - mantissa is an *odd* integer for base 2/8 (not divisible by base).
//     For base 10 it is stripped of trailing zeros.
//   - sign is carried in mantissa (negative mantissa ⇒ negative number).
//   - Special values:
//     ±Inf  → mant=±1 , exp=math.MaxInt32
//     0   → mant=0  , exp=0
//     NaN   → mant=0  , exp=math.MinInt32
func float64Components(f float64, base int) (mant *big.Int, exp int, err error) {
	if base != 2 && base != 8 && base != 10 {
		return nil, 0, mkerr("unsupported base " + itoa(base))
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
		mantStr := replaceAll(parts[0], ".", "") // remove dot
		exp10, _ := atoi(parts[1])
		exp10 -= len(mantStr) - 1 // adjust for removed dot

		// strip trailing zeros from mantissa
		for len(mantStr) > 1 && mantStr[len(mantStr)-1] == '0' {
			mantStr = mantStr[:len(mantStr)-1]
			exp10++
		}
		mant = newBigInt(0)
		mant, _ = mant.SetString(mantStr, 10)
		exp = exp10
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
