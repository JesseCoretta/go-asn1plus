package asn1plus

/*
bs.go contains types and methods pertaining to the ASN.1 BIT
STRING type.
*/

/*
BitString implements the ASN.1 BIT STRING type (tag 3).
*/
type BitString struct {
	Bytes     []byte
	BitLength int
}

/*
NewBitString returns an instance of [BitString] alongside an error
following an attempt to parse x.
*/
func NewBitString(x any, constraints ...Constraint[BitString]) (bs BitString, err error) {
	var raw []byte
	if raw, err = assertBitString(x); err != nil {
		return
	}

	var base int
	if raw, base, err = verifyBitStringContents(raw); err != nil {
		return
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
		err = (ConstraintGroup[BitString](constraints)).Validate(_bs)
	}

	if err == nil {
		bs = _bs
	}
	return
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
func (r BitString) IsPrimitive() bool { return true }

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
func (r BitString) Tag() int { return TagBitString }

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
			err = mkerr("Invalid length for ASN.1 BITSTRING")
			return
		}
		raw = tv
	case string:
		raw = []byte(tv)
	case BitString:
		raw = []byte(tv.Bits())
	default:
		err = mkerr("Invalid type for ASN.1 BITSTRING")
	}
	return
}

func verifyBitStringContents(in []byte) (digits []byte, base int, err error) {
	if len(in) < 2 {
		err = mkerr("input too short for ASN.1 BIT STRING")
		return
	}

	term := in[len(in)-1] // 'B' (bits) or 'H' (hex)
	switch term {
	case 'B', 'b':
		base = 2
	case 'H', 'h':
		base = 16
	default:
		err = mkerr("Incompatible terminating character for ASN.1 BITSTRING: " + string(term))
		return
	}
	// strip terminator
	raw := in[:len(in)-1]

	// must be '<quote><digits>...<quote>'
	if len(raw) < 3 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
		err = mkerr("Incompatible encapsulating characters for ASN.1 BITSTRING")
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
				err = mkerrf("non-binary character in ASN.1 BITSTRING: ", string(c))
			}
		} else { // base == 16
			if !((c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')) {
				err = mkerrf("non-hex character in ASN.1 BITSTRING: ", string(c))
			}
		}
	}

	return
}

func (r BitString) write(pkt Packet, opts Options) (n int, err error) {
	switch t := pkt.Type(); t {
	case BER, DER:
		remainder := r.BitLength % 8 // For 7 bits, remainder = 7.
		unused := 0
		if remainder != 0 {
			unused = 8 - remainder // unused = 1
		}
		bts := make([]byte, 1+len(r.Bytes))
		bts[0] = byte(unused)
		copy(bts[1:], r.Bytes)

		tag, class := effectiveTag(r.Tag(), 0, opts)
		if err = writeTLV(pkt, t.newTLV(class, tag, len(bts), false, bts...), opts); err == nil {
			poff := pkt.Offset()
			n = pkt.Offset() - poff + 1
		}
	}
	return
}

func (r *BitString) read(pkt Packet, tlv TLV, opts Options) (err error) {
	if pkt == nil {
		err = mkerr("Nil Packet encountered during read")
		return
	}

	switch pkt.Type() {
	case BER, DER:
		err = r.readBER(pkt, tlv, opts)
	}

	return
}

func (r *BitString) readBER(pkt Packet, tlv TLV, opts Options) (err error) {
	var data []byte
	if data, err = primitiveCheckRead(r.Tag(), pkt, tlv, opts); err == nil {
		if pkt.Offset()+tlv.Length > pkt.Len() {
			err = errorASN1Expect(pkt.Offset()+tlv.Length, pkt.Len(), "Length")
		} else {
			if len(data) < 1 {
				err = mkerrf(pkt.Type().String(), " BIT STRING is missing the unused bits byte")
				return
			}
			unused := int(data[0])
			if unused < 0 || unused > 7 {
				return mkerrf("Invalid unused bits count: ", itoa(unused))
			}
			r.Bytes = data[1:] // The remaining bytes are the actual bit content.

			// Verify that the padding bits in the last byte are zero.
			if len(r.Bytes) > 0 && unused > 0 {
				lastByte := r.Bytes[len(r.Bytes)-1]
				if lastByte&((1<<unused)-1) != 0 {
					return mkerr("Non-zero padding bits in DER BIT STRING")
				}
			}
			r.BitLength = len(r.Bytes)*8 - unused
			pkt.SetOffset(pkt.Offset() + tlv.Length)
		}
	}

	return
}
