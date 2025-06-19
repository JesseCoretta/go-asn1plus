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
			err = mkerrf("Invalid string value for ASN.1 INTEGER: ", value)
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
		err = group.Constrain(i)
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

func decodeIntegerContent(encoded []byte) (val *big.Int) {
	val = newBigInt(0)
	val.SetBytes(encoded)
	if len(encoded) > 0 && encoded[0]&0x80 != 0 {
		// Compute 2^(len(encoded)*8) and subtract it.
		bitLen := uint(len(encoded) * 8)
		twoPow := new(big.Int).Lsh(newBigInt(1), bitLen)
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

type integerCodec[T any] struct {
	val T
	tag int
	cg  ConstraintGroup[Integer]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[Integer]
	decodeHook   DecodeOverride[Integer]
}

func toInt[T any](v T) Integer   { return *(*Integer)(unsafe.Pointer(&v)) }
func fromInt[T any](i Integer) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *integerCodec[T]) Tag() int          { return c.tag }
func (c *integerCodec[T]) IsPrimitive() bool { return true }
func (c *integerCodec[T]) String() string    { return "IntCodec" }
func (c *integerCodec[T]) getVal() any       { return c.val }
func (c *integerCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

// NOTE: called for both Integer and Enumerated
func (c *integerCodec[T]) write(pkt Packet, o *Options) (off int, err error) {
	if o == nil {
		o = implicitOptions()
	}

	intVal := toInt(c.val)
	if err = c.cg.Constrain(intVal); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(intVal)
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
			tag, cls := effectiveTag(c.tag, 0, o)
			start := pkt.Offset()
			err = writeTLV(pkt, pkt.Type().newTLV(cls, tag, len(wire), false, wire...), o)
			if err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

// NOTE: called for both Integer and Enumerated
func (c *integerCodec[T]) read(pkt Packet, tlv TLV, o *Options) error {
	if o == nil {
		o = implicitOptions()
	}

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {

		decodeVerify := func() (err error) {
			for _, vfn := range c.decodeVerify {
				if err = vfn(wire); err != nil {
					break
				}
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out Integer
			if c.decodeHook != nil {
				out, err = c.decodeHook(wire)
			} else {
				bi := decodeIntegerContent(wire)
				if bi.IsInt64() {
					out = Integer{native: bi.Int64()}
				} else {
					out = Integer{big: true, bigInt: bi}
				}
			}

			if err == nil {
				if err = c.cg.Constrain(out); err == nil {
					c.val = fromInt[T](out)
					pkt.SetOffset(pkt.Offset() + tlv.Length)
				}
			}
		}
	}

	return err
}

func RegisterIntegerAlias[T any](
	tag int,
	verify DecodeVerifier,
	encoder EncodeOverride[Integer],
	decoder DecodeOverride[Integer],
	spec Constraint[Integer],
	user ...Constraint[Integer],
) {
	all := append(ConstraintGroup[Integer]{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &integerCodec[T]{
				tag: tag, cg: all,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
		newWith: func(v any) box {
			return &integerCodec[T]{val: valueOf[T](v),
				tag: tag, cg: all,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
	}

	rt := reflect.TypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterIntegerAlias[Integer](TagInteger, nil, nil, nil, nil)
}
