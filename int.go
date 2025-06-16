package asn1plus

/*
int.go contains all types and methods pertaining to the ASN.1
INTEGER type.
*/

import (
	"math"
	"math/big"
)

/*
Integer implements the unbounded ASN.1 INTEGER type (tag 2). Note
that *[big.Int] is used internally ONLY if the number overflows int64.
*/
type Integer struct {
	big    bool
	native int64    // Stores native integer values
	bigInt *big.Int // Stores big.Int values when necessary
}

/*
Tag returns the integer constant [TagInteger].
*/
func (r Integer) Tag() int { return TagInteger }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r Integer) IsPrimitive() bool { return true }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r Integer) IsZero() bool {
	return &r == nil
}

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
NewInteger returns an instance of [Integer] supporting any signed
magnitude.

Input types may be int, int32, int64, uint64, string or *[math/big.Int].

When the input value is NOT a string and when NO constraints are utilized,
it is safe to shadow the return error.
*/
func NewInteger[T any](v T, constraints ...Constraint[Integer]) (i Integer, err error) {
	switch value := any(v).(type) {
	case int:
		i = Integer{native: int64(value)}
	case int32:
		i = Integer{native: int64(value)}
	case int64:
		i = Integer{native: value}
	case uint64:
		// If the value cannot fit in an int64, use big.Int.
		if value > uint64(math.MaxInt64) {
			i = Integer{big: true, bigInt: newBigInt(0).SetUint64(value)}
		} else {
			i = Integer{native: int64(value)}
		}
	case *big.Int:
		i = Integer{big: true, bigInt: value}
	case string:
		// Attempt to parse the string in base 10.
		if _i, ok := newBigInt(0).SetString(value, 10); !ok {
			err = mkerr("Invalid string value for ASN.1 INTEGER: " + value)
		} else if _i.IsInt64() {
			i = Integer{native: _i.Int64()}
		} else {
			i = Integer{big: true, bigInt: _i}
		}
	case Integer:
		i = value
	default:
		err = mkerr("Unsupported Integer type")
	}

	if len(constraints) > 0 {
		var group ConstraintGroup[Integer] = constraints
		err = group.Validate(i)
	}

	return
}

/*
Big returns the *[big.Int] form of the receiver instance.
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
Eq returns a bool indicative of an equality match between the
receiver instance and x.
*/
func (r Integer) Eq(x Integer) bool {
	return r.Big().Cmp(x.Big()) == 0
}

/*
Eq returns a bool indicative of a negative equality match between
the receiver instance and x.
*/
func (r Integer) Ne(x Integer) bool {
	return r.Big().Cmp(x.Big()) != 0
}

/*
Gt returns a bool indicative of r being greater than x.
*/
func (r Integer) Gt(x Integer) bool {
	return r.Big().Cmp(x.Big()) > 0
}

/*
Ge returns a bool indicative of r being greater than or equal to x.
*/
func (r Integer) Ge(x Integer) bool {
	return r.Big().Cmp(x.Big()) >= 0
}

/*
Lt returns a bool indicative of r being less than x.
*/
func (r Integer) Lt(x Integer) bool {
	return r.Big().Cmp(x.Big()) < 0
}

/*
Le returns a bool indicative of r being less than or equal to x.
*/
func (r Integer) Le(x Integer) bool {
	return r.Big().Cmp(x.Big()) <= 0
}

func (r *Integer) read(pkt Packet, tlv TLV, opts Options) (err error) {
	// Helper to decode a DER‐encoded integer into a *big.Int.
	// This applies the DER sign rule: if the first byte’s MSB is set,
	// the number is considered negative.
	decodeIntValue := func(encoded []byte) *big.Int {
		val := new(big.Int)
		val.SetBytes(encoded)
		if len(encoded) > 0 && encoded[0]&0x80 != 0 {
			// Compute 2^(len(encoded)*8) and subtract it.
			bitLen := uint(len(encoded) * 8)
			twoPow := new(big.Int).Lsh(newBigInt(1), bitLen)
			val.Sub(val, twoPow)
		}
		return val
	}

	if pkt == nil {
		return mkerr("Nil Packet encountered during read")
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts, decodeIntValue)
	default:
		err = mkerr("Encoding rule not support for INTEGER")
	}

	return
}

func (r *Integer) readBER(pkt Packet, tlv TLV, opts Options, decoder func([]byte) *big.Int) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		// len(data) was tlv.Length
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			pkt.SetOffset(pkt.Offset() + tlv.Length)

			val := decoder(data)
			if val.IsInt64() {
				*r = Integer{big: false, native: val.Int64(), bigInt: nil}
			} else {
				*r = Integer{big: true, native: 0, bigInt: val}
			}
		}
	}
	return
}

func (r Integer) write(pkt Packet, opts Options) (n int, err error) {
	var i *big.Int
	if !r.big {
		i = newBigInt(r.native)
	} else {
		i = r.bigInt
	}

	// Compute the DER minimal encoding for i.
	content := encodeIntegerContent(i)

	switch t := pkt.Type(); t {
	case BER, DER:
		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(content), false, content...), opts); err == nil {
			poff := pkt.Offset()
			n = pkt.Offset() - poff + 1
		}
	}

	return
}

func encodeIntegerContent(i *big.Int) (data []byte) {
	if i.Sign() >= 0 {
		// For zero and positive integers, use the big-endian minimal encoding.
		b := i.Bytes()
		if len(b) == 0 {
			// Special case: 0 is encoded as a single 0x00 byte.
			b = []byte{0x00}
		}
		// If the MSB of the first byte is 1, prepend a 0x00 byte to indicate positive.
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		data = b
	} else {
		// For negative integers, we calculate the minimal two's complement representation.
		// First, determine the minimum number of octets n needed.
		abs := new(big.Int).Abs(i)
		n := (abs.BitLen() + 7) / 8
		if n == 0 {
			n = 1 // at least one byte is required
		}
		// For negative numbers, n must be chosen so that i >= - (1 << (8*n - 1)).
		min := new(big.Int).Lsh(newBigInt(1), uint(8*n-1))
		min.Neg(min)
		if i.Cmp(min) < 0 {
			n++ // increase length if i is too small for n octets.
		}
		// Compute 2^(8*n) and add i (note: i is negative), giving the two's complement.
		mod := new(big.Int).Lsh(newBigInt(1), uint(8*n))
		value := new(big.Int).Add(mod, i)
		b := value.Bytes()
		// Ensure the output is exactly n bytes.
		if len(b) < n {
			padding := make([]byte, n-len(b))
			b = append(padding, b...)
		}
		// By DER rules, for negative integers the first byte must have its high bit set.
		if b[0]&0x80 == 0 {
			b = append([]byte{0xff}, b...)
		}
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
		return []byte{0x00}
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
		return 0, mkerr("empty data for INTEGER")
	}

	// Interpret the value in two's complement.
	// Determine if the number is negative from the first byte.
	negative := data[0]&0x80 != 0

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
