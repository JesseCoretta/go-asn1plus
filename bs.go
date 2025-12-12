package asn1plus

/*
bs.go contains types and methods pertaining to the ASN.1 BIT
STRING type.
*/

import (
	"reflect"
	"unsafe"
)

/*
BitString implements the ASN.1 BIT STRING type (tag 3).
*/
type BitString struct {
	Bytes     []byte
	BitLength int
}

/*
BitStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var BitStringConstraintPhase = CodecConstraintDecoding

/*
NewBitString returns an instance of [BitString] alongside an error
following an attempt to parse x.

See also [MustNewBitString].
*/
func NewBitString(x any, constraints ...Constraint) (BitString, error) {
	var (
		raw []byte
		bs  BitString
		err error
	)

	if raw, err = assertBitString(x); err != nil {
		return bs, err
	}

	var base int
	if raw, base, err = verifyBitStringContents(raw); err != nil {
		return bs, err
	}

	var bitLen int
	var bytesOut []byte

	if base == 2 {
		bytesOut, bitLen, err = parseBase2BitString(raw)
	} else {
		// base 16
		bytesOut, bitLen = parseBase16BitString(raw)
	}

	_bs := BitString{Bytes: bytesOut, BitLength: bitLen}
	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(_bs)
	}

	if err == nil {
		bs = _bs
	}
	return bs, err
}

/*
MustNewBitString returns an instance of [BitString] and panics if [NewBitString]
returned an error during processing of x.
*/
func MustNewBitString(x any, constraints ...Constraint) BitString {
	b, err := NewBitString(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

func parseBase2BitString(raw []byte) (bytesOut []byte, bitLen int, err error) {
	bitLen = len(raw)

	fullGroups := bitLen / 8
	remainder := bitLen % 8
	bytesOut = make([]byte, fullGroups)

	for i := 0; i < fullGroups && err == nil; i++ {
		group := string(raw[i*8 : (i+1)*8])
		var v uint64
		if v, err = puint(group, 2, 8); err == nil {
			bytesOut[i] = byte(v)
		}
	}

	if remainder > 0 && err == nil {
		padded := string(raw[fullGroups*8:]) + strrpt("0", 8-remainder)
		var v uint64
		if v, err = puint(padded, 2, 8); err == nil {
			bytesOut = append(bytesOut, byte(v))
		}
	}

	return
}

func parseBase16BitString(raw []byte) (bytesOut []byte, bitLen int) {
	bitLen = len(raw) * 4      // each hex digit = 4 bits
	nBytes := (bitLen + 7) / 8 // round up
	bytesOut = make([]byte, nBytes)

	// walk the hex digits left→right, 4 bits at a time
	byteIdx, nibbleHigh := 0, true
	for _, h := range raw {
		var v byte
		switch {
		case '0' <= h && h <= '9':
			v = h - '0'
		case 'a' <= h && h <= 'f':
			v = h - 'a' + 10
		case 'A' <= h && h <= 'F':
			v = h - 'A' + 10
		}

		if nibbleHigh {
			bytesOut[byteIdx] = v << 4
		} else {
			bytesOut[byteIdx] |= v
			byteIdx++
		}
		nibbleHigh = !nibbleHigh
	}
	// if odd nibble count, low half of last byte is already 0 (padding)
	return
}

/*
Len returns the integer length of the receiver instance.
*/
func (r BitString) Len() int { return len(r.Bytes) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (_ BitString) IsPrimitive() bool { return true }

func bitStringByteToBinary(b byte, width int) string {
	s := fmtInt(int64(b), 2)
	if len(s) < width {
		s = strrpt("0", width-len(s)) + s
	} else if len(s) > width {
		s = s[len(s)-width:]
	}
	return s
}

/*
Bits returns a string representation of the bit value set within the receiver instance.

This method exists solely to satisfy Go's interface signature requirements. See also
[BitString.Bits] and [BitString.Hex].
*/
func (r BitString) String() string { return r.Bits() }

/*
Bits returns a string representation of the bit value set within the receiver instance.
*/
func (r BitString) Bits() string {
	bld := newStrBuilder()
	totalBits := r.BitLength
	for _, b := range r.Bytes {
		if totalBits >= 8 {
			bld.WriteString(bitStringByteToBinary(b, 8))
			totalBits -= 8
		} else if totalBits > 0 {
			bld.WriteString(bitStringByteToBinary(b>>(8-totalBits), totalBits))
			totalBits = 0
		}
	}
	return "'" + bld.String() + "'B"
}

/*
Hex returns a hexadecimal string representation of the bit value set within
the receiver instance.
*/
func (r BitString) Hex() string {
	if r.BitLength == 0 {
		return "''H"
	}

	b := append([]byte(nil), r.Bytes...)
	unused := len(b)*8 - r.BitLength
	if unused > 0 {
		b[len(b)-1] &^= byte((1 << unused) - 1)
	}
	return "'" + uc(hexstr(b)) + "'H"
}

/*
At wraps returns the Nth index of the receiver instance as an int.
*/
func (r BitString) At(idx int) int {
	// DISCLAIMER: Borrowed from encoding/asn1.
	if idx < 0 || idx >= r.BitLength {
		return 0
	}
	x := idx / 8
	y := 7 - uint(idx%8)
	return int(r.Bytes[x]>>y) & 1
}

/*
RightAlign returns the right-aligned instance of [BitString] as an
instance of []byte.
*/
func (r BitString) RightAlign() []byte {
	shift := uint(8 - (r.BitLength % 8))
	if shift == 8 || len(r.Bytes) == 0 {
		return r.Bytes
	}

	a := make([]byte, len(r.Bytes))
	a[0] = r.Bytes[0] >> shift
	for i := 1; i < len(r.Bytes); i++ {
		a[i] = r.Bytes[i-1] << (8 - shift)
		a[i] |= r.Bytes[i] >> shift
	}

	return a
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BitString) IsZero() bool { return len(r.Bytes) == 0 && r.BitLength == 0 }

/*
Tag returns the integer constant [TagBitString] (3).
*/
func (_ BitString) Tag() int { return TagBitString }

/*
Positive returns a Boolean value indicative of bit being in a positive state
within the receiver instance.
*/
func (r BitString) Positive(bit int) bool {
	var posi bool
	if 0 <= bit && bit < r.BitLength && !r.IsZero() {
		byteIndex, bitIndex := bit/8, bit%8
		// In DER encoding, the bit 0 is the most-significant in its byte.
		posi = (r.Bytes[byteIndex] & (1 << (7 - bitIndex))) != 0
	}
	return posi
}

/*
Set sets the Nth bit within the receiver instance via a left shift.
*/
func (r *BitString) Set(bit int) {
	if 0 <= bit && bit < r.BitLength && !r.IsZero() {
		byteIndex, bitIndex := bit/8, bit%8
		mask := byte(1 << (7 - bitIndex))
		r.Bytes[byteIndex] |= mask
	}
}

/*
Unset unsets the Nth bit within the receiver instance via a right shift.
*/
func (r *BitString) Unset(bit int) {
	if 0 <= bit && bit < r.BitLength && !r.IsZero() {
		byteIndex, bitIndex := bit/8, bit%8
		mask := byte(1 << (7 - bitIndex))
		r.Bytes[byteIndex] &^= mask
	}
}

/*
NamedBit defines a single bit with its name and the bit index (0-based).
*/
type NamedBit struct {
	Name string // a human-readable name for the flag
	Bit  int    // the bit position (0-based; 0 is the most-significant)
}

/*
NamedBits provides a base implementation for ASN.1 BITSTRING types which
represent a set of named flags. It embeds the native [BitString] and a
slice of bit definitions.

During string representation, instances of this type will return the
entire structure if [BitString] is not set. Otherwise, the process of
string representation will be limited to only those [NamedBit] slices
which are currently set within [BitString].
*/
type NamedBits struct {
	BitString            // embedded BitString
	Bits      []NamedBit // user-populated NamedBit registry
}

/*
String returns the string representation of the receiver instance.
*/
func (r NamedBits) String() string {

	getSetBit := func(bit NamedBit) (s string) {
		if len(r.BitString.Bytes) > 0 {
			if r.BitString.Positive(bit.Bit) {
				s = string(rune(32)) + bit.Name + `(` + itoa(bit.Bit) + `)`
			}
		} else {
			s = string(rune(32)) + bit.Name + `(` + itoa(bit.Bit) + `)`
		}
		return s
	}

	str := newStrBuilder()
	str.WriteRune('{')
	str.WriteRune(10)

	slice := []string{}
	for i := 0; i < len(r.Bits); i++ {
		if got := getSetBit(r.Bits[i]); got != "" {
			slice = append(slice, got)
		}
	}

	str.WriteString(join(slice, `,`+string(rune(10))))
	str.WriteRune(10)
	str.WriteRune('}')

	return str.String()
}

/*
Positive returns a Boolean value indicative of bit being in a positive state
within the receiver instance.
*/
func (r NamedBits) Positive(name string) bool {
	var posi bool
	for _, bit := range r.Bits {
		if streqf(bit.Name, name) {
			posi = r.BitString.Positive(bit.Bit)
			break
		}
	}
	return posi
}

/*
Set sets the Nth bit within the receiver instance via a left shift.
*/
func (r *NamedBits) Set(name string) {
	for _, bit := range r.Bits {
		if streqf(bit.Name, name) {
			r.BitString.Set(bit.Bit)
			break
		}
	}
}

/*
Unset unsets the Nth bit within the receiver instance via a right shift.
*/
func (r *NamedBits) Unset(name string) {
	for _, bit := range r.Bits {
		if streqf(bit.Name, name) {
			r.BitString.Unset(bit.Bit)
			break
		}
	}
}

/*
Names returns slices of string bit names that are currently in a positive
state within the receiver instance.
*/
func (r NamedBits) Names() []string {
	var names []string
	for _, bit := range r.Bits {
		if r.BitString.Positive(bit.Bit) {
			names = append(names, bit.Name)
		}
	}

	return names
}

func assertBitString(x any) (raw []byte, err error) {
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			err = primitiveErrorf("BIT STRING: invalid length")
			return
		}
		raw = tv
	case string:
		raw = []byte(tv)
	case BitString:
		raw = []byte(tv.Bits())
	case Primitive:
		raw = []byte(tv.String())
	default:
		err = errorBadTypeForConstructor("BIT STRING", x)
	}
	return
}

func verifyBitStringContents(in []byte) (digits []byte, base int, err error) {
	if len(in) < 2 {
		err = primitiveErrorf("BIT STRING: input too short")
		return
	}

	term := in[len(in)-1] // 'B' (bits) or 'H' (hex)
	switch term {
	case 'B', 'b':
		base = 2
	case 'H', 'h':
		base = 16
	default:
		err = primitiveErrorf("BIT STRING: incompatible terminating character: " + string(term))
		return
	}
	// strip terminator
	raw := in[:len(in)-1]

	// must be '<quote><digits>...<quote>'
	if len(raw) < 3 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
		err = primitiveErrorf("BIT STRING: incompatible encapsulating characters")
		return
	}
	digits = raw[1 : len(raw)-1]

	// validate digit set
	err = verifyBitStringDigitSet(base, digits)
	return
}

func verifyBitStringDigitSet(base int, digits []byte) (err error) {
	for i := 0; i < len(digits) && err == nil; i++ {
		c := digits[i]
		if base == 2 {
			if c != '0' && c != '1' {
				err = primitiveErrorf("BIT STRING: non-binary character: ", string(c))
			}
		} else { // base == 16
			if !((c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')) {
				err = primitiveErrorf("BIT STRING: non-hex character: ", string(c))
			}
		}
	}

	return
}

type bitStringCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *bitStringCodec[T]) Tag() int          { return c.tag }
func (c *bitStringCodec[T]) IsPrimitive() bool { return true }
func (c *bitStringCodec[T]) String() string    { return "bitStringCodec" }
func (c *bitStringCodec[T]) getVal() any       { return c.val }
func (c *bitStringCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func toBitString[T any](v T) BitString   { return *(*BitString)(unsafe.Pointer(&v)) }
func fromBitString[T any](i BitString) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *bitStringCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, DER:
		n, err = bcdBitStringWrite(c, pkt, o)
	case CER:
		if c.Tag() == TagBitString && len(toBitString(c.val).Bytes) > 1000 {
			n, err = cerSegmentedBitStringWrite(c, pkt, o)
		} else {
			n, err = bcdBitStringWrite(c, pkt, o)
		}
	default:
		err = errorRuleNotImplemented
	}

	return
}

func bcdBitStringWrite[T any](c *bitStringCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		bsVal := toBitString(c.val)
		remainder := bsVal.BitLength % 8
		unused := 0
		if remainder != 0 {
			unused = 8 - remainder
		}

		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			wire = make([]byte, 1+len(bsVal.Bytes))
			wire[0] = byte(unused)
			copy(wire[1:], bsVal.Bytes)
		}

		tag, cls := effectiveHeader(c.tag, 0, o)
		start := pkt.Offset()
		if err == nil {
			tlv := pkt.Type().newTLV(cls, tag, len(wire), false, wire...)
			err = writeTLV(pkt, tlv, o)
			off = pkt.Offset() - start
		}
	}

	return
}

func (c *bitStringCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, DER:
		err = bcdBitStringRead(c, pkt, tlv, o)
	case CER:
		if tlv.Compound && tlv.Length < 0 && tlv.Tag == TagBitString {
			err = cerSegmentedBitStringRead(c, pkt, tlv, o)
		} else {
			err = bcdBitStringRead(c, pkt, tlv, o)
		}
	default:
		err = errorRuleNotImplemented
	}

	return
}

func bcdBitStringRead[T any](c *bitStringCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	// Reject primitives encoded with indefinite length
	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {
		if len(wire) < 1 {
			err = primitiveErrorf("BIT STRING: missing unused-bits byte")
			return err
		}

		unused := int(wire[0])
		if unused < 0 || unused > 7 {
			err = primitiveErrorf("BIT STRING: unused bits outside 0-7")
			return err
		}

		bits := wire[1:]
		if len(bits) == 0 && unused != 0 {
			err = primitiveErrorf("BIT STRING: unused bits > length")
			return err
		}

		// DER: padding bits MUST be zero
		if err = bitStringCheckDERPadding(pkt.Type(), bits, unused); err != nil {
			return err
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
				out = fromBitString[T](BitString{
					Bytes:     append([]byte(nil), bits...),
					BitLength: len(bits)*8 - unused,
				})
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

func bitStringCheckDERPadding(rule EncodingRule, bits []byte, unused int) (err error) {
	if rule == DER && len(bits) > 0 && unused > 0 {
		last := bits[len(bits)-1]
		if last&((1<<unused)-1) != 0 {
			err = primitiveErrorf("DER BIT STRING: non-zero padding")
		}
	}

	return
}

func RegisterBitStringAlias[T any](
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
			return &bitStringCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
		newWith: func(v any) box {
			return &bitStringCodec[T]{
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
	RegisterBitStringAlias[BitString](TagBitString,
		BitStringConstraintPhase,
		nil, nil, nil, nil)
}
