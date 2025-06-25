package asn1plus

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestBitString_customType(t *testing.T) {
	type CustomBits BitString
	RegisterBitStringAlias[CustomBits](TagBitString, nil, nil, nil, nil)

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	orig, _ := NewBitString(`'10100101'B`)
	cust := CustomBits(orig)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out CustomBits
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	// We cheat again, since we didn't write a
	// custom Bits method for this simple test.
	want := BitString(cust).Bits()
	got := BitString(out).Bits()
	if want != got {
		t.Fatalf("%s failed [BER bit string cmp.]:\n\twant: %s\n\tgot:  %s",
			t.Name(), want, got)
	}
	unregisterType(refTypeOf(cust))
}

func TestBitString(t *testing.T) {
	for idx, want := range []string{
		`'10100101'B`,
	} {
		if bs, err := NewBitString(want); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if bs.IsZero() {
			t.Errorf("%s[%d] failed: instance is zero", t.Name(), idx)
		} else if got := bs.Bits(); want != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, want, got)
		}
	}

	for _, rule := range encodingRules {
		bs, err := NewBitString(`'101001'B`)
		if err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		}

		bs.Tag()
		bs.IsPrimitive()

		pkt, _ := Marshal(bs, With(rule))
		var bs2 BitString
		_ = Unmarshal(pkt, &bs2)
		pkt.SetOffset()
	}

	_, _ = NewBitString([]byte(`'1010111'B`))
	_, _ = NewBitString([]byte(``))
	_, _ = NewBitString([]byte(`"1010101"B`))
	verifyBitStringContents([]byte(`''B`))
}

/*
This example demonstrates the means for creating an instance of [BitString]
using string bit input, as well as for expressing that instance of [BitString]
as a hexadecimal string value.
*/
func ExampleBitString_byBits() {
	bs, err := NewBitString(`'11101100'B`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", bs.Hex()) // show hex representation
	// Output: 'EC'H
}

/*
This example demonstrates the means for creating an instance of [BitString]
using hexadecimal string input, as well as for expressing that instance of
[BitString] as string bits.
*/
func ExampleBitString_byHex() {
	bs, err := NewBitString(`'EC'H`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", bs.Bits()) // show bit representation
	// Output: '11101100'B
}

func TestNewBitString_Success(t *testing.T) {
	input := "'101010'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) returned error: %v", input, err)
	}
	if bs.BitLength != 6 {
		t.Errorf("Expected BitLength = 6, got %d", bs.BitLength)
	}
	if len(bs.Bytes) != 1 {
		t.Errorf("Expected 1 byte, got %d", len(bs.Bytes))
	}
	if s := bs.Bits(); s != input {
		t.Errorf("Expected String() = %q, got %q", input, s)
	}
}

func TestNewBitString_Failure_BadTerminator(t *testing.T) {
	var input any = "'101010'"
	_, err := NewBitString(input)
	if err == nil {
		t.Errorf("Expected error for input %q, but got nil", input)
	}

	input = struct{}{}
	if _, err = NewBitString(input); err == nil {
		t.Errorf("Expected error for input %q, but got nil", input)
	}
}

func TestNewBitString_Failure_NonBinary(t *testing.T) {
	input := "'10a010'B"
	_, err := NewBitString(input)
	if err == nil {
		t.Errorf("Expected error for non-binary input %q, but got nil", input)
	}
}

func TestBitString_AtAndPositive(t *testing.T) {
	input := "'101010'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) error: %v", input, err)
	}
	expected := []int{1, 0, 1, 0, 1, 0}
	for idx, exp := range expected {
		if bit := bs.At(idx); bit != exp {
			t.Errorf("At(%d): expected %d, got %d", idx, exp, bit)
		}
		if (exp == 1) != bs.Positive(idx) {
			t.Errorf("Positive(%d): expected %v, got %v", idx, exp == 1, bs.Positive(idx))
		}
	}
}

func TestBitString_SetUnset(t *testing.T) {
	input := "'101010'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) error: %v", input, err)
	}

	if bs.Positive(1) {
		t.Errorf("Expected bit 1 to be false initially")
	}

	bs.Set(1)
	if !bs.Positive(1) {
		t.Errorf("Expected bit 1 to be true after shift")
	}

	bs.Unset(0)
	if bs.Positive(0) {
		t.Errorf("Expected bit 0 to be false after unshift")
	}
}

func TestRightAlign(t *testing.T) {
	input := "'101010'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) error: %v", input, err)
	}
	rightAligned := bs.RightAlign()
	expected := []byte{42}
	if !reflect.DeepEqual(rightAligned, expected) {
		t.Errorf("RightAlign: expected %v, got %v", expected, rightAligned)
	}
}

func TestNamedBits_Positive(t *testing.T) {
	input := "'101010'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) error: %v", input, err)
	}

	nb := NamedBits{
		BitString: bs,
		Bits: []NamedBit{
			{Name: "first", Bit: 0},
			{Name: "second", Bit: 1},
			{Name: "third", Bit: 2},
			{Name: "fourth", Bit: 3},
			{Name: "fifth", Bit: 4},
			{Name: "sixth", Bit: 5},
		},
	}

	shouldBeTrue := []string{"first", "third", "fifth"}
	shouldBeFalse := []string{"second", "fourth", "sixth"}

	for _, name := range shouldBeTrue {
		if !nb.Positive(name) {
			t.Errorf("Expected flag %q to be positive", name)
		}
	}
	for _, name := range shouldBeFalse {
		if nb.Positive(name) {
			t.Errorf("Expected flag %q to be false", name)
		}
	}
}

func TestNamedBits_SetUnsetAndNames(t *testing.T) {
	input := "'00000000'B"
	bs, err := NewBitString(input)
	if err != nil {
		t.Fatalf("NewBitString(%q) error: %v", input, err)
	}
	nb := NamedBits{
		BitString: bs,
		Bits: []NamedBit{
			{Name: "alpha", Bit: 0},
			{Name: "beta", Bit: 1},
			{Name: "gamma", Bit: 2},
			{Name: "delta", Bit: 3},
		},
	}

	if names := nb.Names(); len(names) != 0 {
		t.Errorf("Expected no flags set initially, got %v", names)
	}

	nb.Set("alpha")
	nb.Set("gamma")
	if !nb.Positive("alpha") {
		t.Errorf("Expected 'alpha' to be set")
	}
	if !nb.Positive("gamma") {
		t.Errorf("Expected 'gamma' to be set")
	}

	expectedNames := []string{"alpha", "gamma"}
	gotNames := nb.Names()
	if !reflect.DeepEqual(gotNames, expectedNames) {
		t.Errorf("Expected Names() = %v, got %v", expectedNames, gotNames)
	}

	nb.Unset("alpha")
	if nb.Positive("alpha") {
		t.Errorf("Expected 'alpha' to be cleared")
	}

	expectedNames = []string{"gamma"}
	gotNames = nb.Names()
	if !reflect.DeepEqual(gotNames, expectedNames) {
		t.Errorf("After unshift, expected Names() = %v, got %v", expectedNames, gotNames)
	}
}

func TestBitStringByteToBinary_Padding(t *testing.T) {
	got := bitStringByteToBinary(3, 8)
	want := "00000011"
	if got != want {
		t.Errorf("bitStringByteToBinary(3,8) = %q; want %q", got, want)
	}
}

func TestBitStringByteToBinary_Trimming(t *testing.T) {
	got := bitStringByteToBinary(5, 2)
	want := "01"
	if got != want {
		t.Errorf("bitStringByteToBinary(5,2) = %q; want %q", got, want)
	}
}

func TestBitStringByteToBinary_Exact(t *testing.T) {
	got := bitStringByteToBinary(3, 2)
	want := "11"
	if got != want {
		t.Errorf("bitStringByteToBinary(3,2) = %q; want %q", got, want)
	}
}

func TestBitString_String_FullByte(t *testing.T) {
	bs := BitString{
		Bytes:     []byte{0x03},
		BitLength: 8,
	}
	got := bs.Bits()
	want := "'00000011'B"
	if got != want {
		t.Errorf("BitString.Bits() = %q; want %q", got, want)
	}
}

func TestBitString_String_Partial(t *testing.T) {
	bs := BitString{
		Bytes:     []byte{0x03},
		BitLength: 4,
	}
	got := bs.Bits()
	want := "'0000'B"
	if got != want {
		t.Errorf("BitString.Bits() = %q; want %q", got, want)
	}
}

func TestBitString_String_MultiByte(t *testing.T) {
	bs := BitString{
		Bytes:     []byte{0xAB, 0xC0},
		BitLength: 12,
	}
	got := bs.Bits()
	want := "'101010111100'B"
	if got != want {
		t.Errorf("BitString.Bits() = %q; want %q", got, want)
	}
}

func TestBitString_codecov(_ *testing.T) {
	var bs BitString
	bs.Len()
	bs.Hex()
	bs.Bits()
	_ = bs.String()

	nb := NamedBits{
		Bits: []NamedBit{
			{Name: "apple", Bit: 0},
			{Name: "avocado", Bit: 1},
			{Name: "tomato", Bit: 2},
		},
	}
	_ = nb.String()
	verifyBitStringContents([]byte{0x00})

	if f, ok := master[refTypeOf(BitString{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(BitString{}).(box)
	}

	_, _ = NewBitString(struct{}{})
	bc := new(bitStringCodec[BitString])
	bc.encodeHook = func(b BitString) ([]byte, error) {
		return b.Bytes, nil
	}
	bc.decodeHook = func(b []byte) (BitString, error) {
		return BitString{Bytes: []byte{0x1, 0x2}, BitLength: 2 * 8}, nil
	}
	bc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	bc.IsPrimitive()
	_ = bc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = bc.write(tpkt, nil)
	_, _ = bc.write(bpkt, nil)
	bc.read(tpkt, TLV{}, nil)

	bitStringCheckDERPadding(DER, []byte{0x1, 0x0, 0x0, 0x1, 0x1}, 4)
	assertBitString(OctetString("test"))
	verifyBitStringDigitSet(8, []byte{0x1, 0xf, 0x0, 0x0, 0xe, 0xd})
}

type customBitString BitString

func (_ customBitString) Tag() int          { return TagBitString }
func (_ customBitString) String() string    { return `` }
func (_ customBitString) IsPrimitive() bool { return true }

func TestCustomBitString_withControls(t *testing.T) {
	RegisterBitStringAlias[customBitString](TagBitString,
		func([]byte) error {
			return nil
		},
		func(customBitString) ([]byte, error) {
			return []byte{0x1, 0x1, 0xFF}, nil
		},
		func([]byte) (customBitString, error) {
			return customBitString{Bytes: []byte{0x1, 0x2}, BitLength: 2 * 8}, nil
		},
		nil)

	var cust customBitString = customBitString{Bytes: []byte{0x1, 0x2}, BitLength: 2 * 8}

	pkt, err := Marshal(cust, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var next customBitString
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func ExampleNamedBits() {
	var bs BitString = BitString{
		Bytes:     []byte{0x00},
		BitLength: 8,
	}
	bs.Set(0)
	bs.Set(1)

	fmt.Printf("ASN.1 BIT STRING: %s (hex: %s)\n", bs.Bits(), bs.Hex())

	// When setting an instance of NamedBits,
	// if BitString is set with a value, only
	// the positive bits will be printed for
	// string representation. Without a value,
	// the entire index is printed.
	nb := NamedBits{
		BitString: bs,
		Bits: []NamedBit{
			{Name: "apple", Bit: 0},
			{Name: "avocado", Bit: 1},
			{Name: "tomato", Bit: 2},
		},
	}

	// Verify Positive (set) bits are indeed set.
	shouldBeTrue := []string{"apple", "avocado"}
	for _, name := range shouldBeTrue {
		if !nb.Positive(name) {
			fmt.Printf("Expected flag %q to be positive", name)
			return
		}
	}

	// Verify Negative (unset) bits are NOT set.
	shouldBeFalse := []string{"tomato"}
	for _, name := range shouldBeFalse {
		if nb.Positive(name) {
			fmt.Printf("Expected flag %q to be negative", name)
		}
	}

	fmt.Printf("NAMED BITS: %s\n", nb)
	// Output:
	// ASN.1 BIT STRING: '11000000'B (hex: 'C0'H)
	// NAMED BITS: {
	//  apple(0),
	//  avocado(1)
	// }
}

func TestBitStringAt_OutOfRange(t *testing.T) {
	bs := BitString{
		Bytes:     []byte{0xFF}, // 8 bits, all 1s
		BitLength: 8,
	}

	if got := bs.At(-1); got != 0 {
		t.Fatalf("At(-1): expected 0, got %d", got)
	}
	if got := bs.At(8); got != 0 { // valid indices: 0-7
		t.Fatalf("At(8): expected 0, got %d", got)
	}
}

func TestBitStringRightAlign_EarlyReturnShift8(t *testing.T) {
	src := []byte{0x12, 0x34}
	bs := BitString{
		Bytes:     src,
		BitLength: 16, // multiple of 8 ⇒ shift == 8
	}

	out := bs.RightAlign()
	if !bytes.Equal(out, src) {
		t.Fatalf("expected identical slice % X, got % X", src, out)
	}
}

func TestBitStringRightAlign_EarlyReturnEmpty(t *testing.T) {
	bs := BitString{Bytes: nil, BitLength: 0}
	out := bs.RightAlign()
	if out != nil {
		t.Fatalf("empty input should yield nil/empty slice, got % X", out)
	}
}

func TestBitStringRightAlign_ShiftAndMerge(t *testing.T) {
	/*
	   Choose 10-bit BitString:

	       Bytes      = [0xAA, 0xC0]  (10101010 11000000)
	       BitLength  = 10
	       shift      = 8 - (10 % 8) = 6

	   Expected right-aligned bytes:
	       a[0] = 0xAA >> 6                        = 0x02
	       a[1] = (0xAA << 2) | (0xC0 >> 6)       = 0xA8 | 0x03 = 0xAB
	*/
	bs := BitString{
		Bytes:     []byte{0xAA, 0xC0},
		BitLength: 10,
	}
	want := []byte{0x02, 0xAB}

	got := bs.RightAlign()
	if !bytes.Equal(got, want) {
		t.Fatalf("rightAlign mismatch: got % X, want % X", got, want)
	}
}

// ExampleBitString_withConstraints demonstrates four independent BIT STRING
// constraints:
//
//   - bit-length constraint (1 ... 8 bits)
//   - subset-of mask constraint
//   - even-bit content constraint
//   - successful acceptance of a value that meets them all
func ExampleBitString_withConstraints() {
	// bit-length constraint – allow 1 ... 8 bits
	cBitLength := func(bs BitString) error {
		if bs.BitLength < 1 || bs.BitLength > 8 {
			return fmt.Errorf("size %d is out of bounds [1, 8]", bs.BitLength)
		}
		return nil
	}

	// subset-of constraint – only bits 0 & 1
	mask, _ := NewBitString("'C0'H")
	cSubset := func(bs BitString) error {
		for i := 0; i < bs.BitLength; i++ {
			if bs.At(i) == 1 && mask.At(i) == 0 {
				return fmt.Errorf("constraint violation: bit %d not permitted", i)
			}
		}
		return nil
	}

	// even-bit rule – only even positions 1
	cEven := func(bs BitString) error {
		for i := 0; i < bs.BitLength; i++ {
			if i%2 == 1 && bs.At(i) == 1 {
				return fmt.Errorf("constraint violation: only even-numbered bits may be 1 (got bit %d)", i)
			}
		}
		return nil
	}

	// Test three literals
	for _, lit := range []string{
		"'AAC0'H", // 16 bits -- size violation
		"'A0'H",   // bit 2 set -- subset violation
		"'80'H",   // 10000000₂ passes all constraints
	} {
		_, err := NewBitString(lit, cBitLength, cSubset, cEven)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("%s accepted\n", lit)
		}
	}

	// Output:
	// size 16 is out of bounds [1, 8]
	// constraint violation: bit 2 not permitted
	// '80'H accepted
}

func TestBitStringHex_PaddingMask(t *testing.T) {
	/*
	   Bytes:      [0xAB, 0xCD]  → 10101011 11001101₂
	   BitLength:  12            → unused = 16-12 = 4

	   Hex() should clear the low 4 bits of the last byte:
	       0xCD → 0xC0

	   Expected final byte slice: [0xAB, 0xC0] → "ABC0"
	*/
	bs := BitString{
		Bytes:     []byte{0xAB, 0xCD},
		BitLength: 12,
	}

	got := bs.Hex()
	want := "'ABC0'H"

	if got != want {
		t.Fatalf("Hex(): got %s, want %s", got, want)
	}
}

func TestBitString_encodingRules(t *testing.T) {
	for idx, value := range []any{
		`'10101'B`,
		`'EC'H`,
		[]byte(`'10101'B`),
		[]byte(`'EC'H`),
		BitString{
			Bytes:     []byte{0xAB, 0xCD},
			BitLength: 12,
		},
	} {
		for _, rule := range encodingRules {
			bs, err := NewBitString(value)
			if err != nil {
				t.Fatalf("%s[%d] failed [%s NewBitString]: %v", t.Name(), idx, rule, err)
			}

			var pkt Packet
			if pkt, err = Marshal(bs, With(rule)); err != nil {
				t.Fatalf("%s[%d] failed [%s encoding]: %v", t.Name(), idx, rule, err)
			}

			var bs2 BitString
			if err = Unmarshal(pkt, &bs2); err != nil {
				t.Fatalf("%s[%d] failed [%s decoding]: %v", t.Name(), idx, rule, err)
			}
		}
	}
}

func TestPacket_LargeBitStringCER(t *testing.T) {
	data := []byte(strrpt("Y", 2001))
	large := BitString{
		Bytes:     data,
		BitLength: len(data) * 8,
	}

	pkt, err := Marshal(large, With(CER))
	if err != nil {
		t.Fatalf("%s failed [CER encoding]: %v", t.Name(), err)
	}

	var alsoLarge BitString
	if err = Unmarshal(pkt, &alsoLarge); err != nil {
		t.Fatalf("%s failed [CER decoding]: %v", t.Name(), err)
	}

	if large.BitLength != alsoLarge.BitLength {
		t.Fatalf("%s failed [CER large BitString size cmp.]:\n\twant: %d bits\n\tgot:  %d bits",
			t.Name(), large.BitLength, alsoLarge.BitLength)
	}

	if !bytes.Equal(large.Bytes, alsoLarge.Bytes) {
		t.Fatalf("%s failed [CER large BitString contents cmp.]: contents differ", t.Name())
	}
}
