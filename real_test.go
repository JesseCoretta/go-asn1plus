package asn1plus

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"testing"
)

func ExampleReal_String() {
	r, err := NewReal(314159, 10, -5)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(r.String())
	// Output:
	// {mantissa 314159, base 10, exponent -5}
}

func ExampleReal_Big() {
	r, err := NewReal(314159, 10, -5)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(r.Big().String())
	// Output: 3.14159
}

func ExampleReal_Float() {
	r, err := NewReal(314159, 10, -5)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%.05f", r.Float())
	// Output: 3.14159
}

func ExampleNewRealPlusInfinity() {
	r := NewRealPlusInfinity()
	fmt.Println(r.Big().String())
	// Output: +Inf
}

func ExampleNewRealMinusInfinity() {
	r := NewRealMinusInfinity()
	fmt.Println(r.Big().String())
	// Output: -Inf
}

func TestReal_encodingRules(t *testing.T) {
	for _, rule := range encodingRules {
		rOrig, err := NewReal(314159, 10, -5)
		if err != nil {
			t.Errorf("NewReal error: %v", err)
			return
		}
		rOrig.Tag()
		rOrig.IsPrimitive()

		var pkt PDU
		if pkt, err = Marshal(rOrig, With(rule)); err != nil {
			t.Errorf("%s failed [%s encode]: %v", t.Name(), rule, err)
			return
		}

		var rDecoded Real
		if err = Unmarshal(pkt, &rDecoded); err != nil {
			t.Errorf("%s failed [%s decode]: %v", t.Name(), rule, err)
			return
		}

		origMantissa := rOrig.Mantissa.Big().Abs(rOrig.Mantissa.Big())
		decMantissa := rDecoded.Mantissa.Big().Abs(rDecoded.Mantissa.Big())
		if origMantissa.Cmp(decMantissa) != 0 {
			t.Errorf("Mantissa mismatch: expected %s, got %s", origMantissa.String(), decMantissa.String())
		}
		if rOrig.Exponent != rDecoded.Exponent {
			t.Errorf("Exponent mismatch: expected %d, got %d", rOrig.Exponent, rDecoded.Exponent)
		}
	}
}

func TestRealSpecial_encodingRules(t *testing.T) {
	posOrNeg := func(i int) string {
		if i == 0 {
			return "positive infinity"
		}
		return "negative infinity"
	}

	for idx, inf := range []Real{
		NewRealPlusInfinity(),
		NewRealMinusInfinity(),
	} {
		for _, rule := range encodingRules {
			var pkt PDU
			var err error
			if pkt, err = Marshal(inf, With(rule)); err != nil {
				t.Fatalf("%s failed [%s encode infinity]: %v", t.Name(), rule, err)
			}

			var rDecoded Real
			if err = Unmarshal(pkt, &rDecoded); err != nil {
				t.Fatalf("%s[%s] failed [%s decode infinity]: %v", t.Name(), posOrNeg(idx), rule, err)
			}

			// Check that the content octet is 0x40.
			if idx == 0 {
				if data := pkt.Data(); data[2] != 0x40 {
					t.Fatalf("Expected PLUS-INFINITY content 0x40, got 0x%02x", data[2])
				}
			} else {
				if data := pkt.Data(); data[2] != 0x41 {
					t.Fatalf("Expected MINUS-INFINITY content 0x41, got 0x%02x", data[2])
				}
			}
		}
	}
}

func TestRealZeroEncoding(t *testing.T) {
	zeroInt, err := NewInteger(0)
	if err != nil {
		t.Fatalf("NewInteger error: %v", err)
	}

	// A zero REAL is represented as {Special: RealNormal, with zero Mantissa}.
	r := Real{
		Special:  RealNormal,
		Mantissa: zeroInt,
		Base:     2,
		Exponent: 0,
	}
	pkt, err := Marshal(r)
	if err != nil {
		t.Fatalf("Error encoding zero REAL: %v", err)
	}
	// Zero is encoded with a content length of zero (i.e. two bytes: tag and length).
	if pkt.Offset() != 2 {
		t.Errorf("Expected 2 bytes for zero REAL, got %d", pkt.Offset())
	}
	if pkt.Data()[1] != 0 {
		t.Errorf("Expected length byte 0 for zero REAL, got %d", pkt.Data()[1])
	}
}

func TestRealStringMethod(t *testing.T) {
	r, err := NewReal(314159, 10, -5)
	if err != nil {
		t.Fatalf("NewReal error: %v", err)
	}
	expected := "{mantissa 314159, base 10, exponent -5}"
	if r.String() != expected {
		t.Errorf("Expected %q, got %q", expected, r.String())
	}

	// Special values.
	if NewRealPlusInfinity().String() != "PLUS-INFINITY" {
		t.Errorf("PLUS-INFINITY string mismatch")
	}
	if NewRealMinusInfinity().String() != "MINUS-INFINITY" {
		t.Errorf("MINUS-INFINITY string mismatch")
	}
}

func TestRealDeepEqual_encodingRules(t *testing.T) {
	for _, rule := range encodingRules {
		// Create a Real value with a nonzero mantissa.
		rOne, err := NewReal(1234567, 10, 3)
		if err != nil {
			t.Fatalf("%s failed [%s NewReal]: %v", t.Name(), rule, err)
		}

		var pkt PDU
		if pkt, err = Marshal(rOne, With(rule)); err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		var rTwo Real
		if err = Unmarshal(pkt, &rTwo); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}

		// We compare without considering the Base field, as our encoder forces base = 2.
		if rOne.Exponent != rTwo.Exponent {
			t.Fatalf("%s failed [%s exponent cmp.]\n\twant: %d\n\tgot:  %d",
				t.Name(), rule, rOne.Exponent, rTwo.Exponent)
		}

		// Compare absolute values of the mantissas.
		origAbs := rOne.Mantissa.Big().Abs(rOne.Mantissa.Big())
		decAbs := rTwo.Mantissa.Big().Abs(rTwo.Mantissa.Big())

		if origAbs.Cmp(decAbs) != 0 {
			t.Fatalf("%s failed [%s mantissa cmp]: want: '%s', got:  '%s'",
				t.Name(), rule, origAbs.String(), decAbs.String())
		}

		f1 := rOne.Big()
		f2 := rTwo.Big()

		if f1.Cmp(f2) != 0 {
			t.Fatalf("%s failed [%s float cmp.]:\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, f1.String(), f2.String())
		}
	}
}

func TestRealDecodeErrors(t *testing.T) {
	// Prepare an invalid DER packet: truncated REAL.
	pkt := &BERPacket{data: []byte{byte(TagReal), 2, 0x80}, offset: 0}
	var out Real
	err := Unmarshal(pkt, &out)
	if err == nil {
		t.Errorf("Expected error for truncated REAL, but got none")
	}
}

func TestReal_codecov(_ *testing.T) {
	decodeRealExponent([]byte(`blahjfksefhjshk`))
	_, _, _ = float64ToRealParts(float64(0), 2)
	_, _, _ = bigFloatToRealParts(big.NewFloat(0), 2)

	NewRealPlusInfinity().Float()
	NewRealMinusInfinity().Float()
	encodeRealExponent(-1)
	encodeRealExponent(0)
	encodeRealExponent(1)

	zeroInt, _ := NewInteger(0)
	r := Real{
		Special:  RealNormal,
		Mantissa: zeroInt,
		Base:     2,
		Exponent: 0,
	}

	byteToInfinity(0x02)

	encodeMantissa(new(big.Int))
	float64Components(float64(3.1415900000), 10)
	float64Components(float64(3.1415900000), 16)

	rc := new(realCodec[Real])
	rc.encodeHook = func(b Real) ([]byte, error) {
		return []byte{0x9, 0x5, 0xc1, 0x3, 0x12, 0xd6, 0x87}, nil
	}
	rc.decodeHook = func(b []byte) (Real, error) {
		return r, nil
	}
	rc.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}

	if f, ok := master[refTypeOf(Real{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(Real{}).(box)
	}

	rc.IsPrimitive()
	rc.Tag()
	_ = rc.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = rc.write(tpkt, nil)
	_, _ = rc.write(bpkt, nil)
	rc.read(tpkt, TLV{}, nil)
	rc.read(bpkt, TLV{}, nil)

	realBaseToHeader(2)
	realBaseToHeader(8)
	realBaseToHeader(10)
	realBaseToHeader(16)
	realHeaderToBase(0x00)
	realHeaderToBase(0x40)
	realHeaderToBase(0x80)
	realHeaderToBase(0xC0)
}

type customReal Real

func (_ customReal) Tag() int          { return TagReal }
func (_ customReal) String() string    { return `` }
func (_ customReal) IsPrimitive() bool { return true }

func TestCustomReal_withControls(t *testing.T) {
	orig, _ := NewReal(314159, 10, -5)
	var cust customReal = customReal(orig) // cheat

	RegisterRealAlias[customReal](TagReal,
		func([]byte) error {
			return nil
		},
		func(customReal) ([]byte, error) {
			return []byte{0x9, 0x5, 0xc1, 0x3, 0x12, 0xd6, 0x87}, nil
		},
		func([]byte) (customReal, error) {
			return cust, nil
		},
		nil)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customReal
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func reconstruct(mant *big.Int, base int, exp int) float64 {
	switch exp {
	case math.MaxInt32:
		if mant.Sign() < 0 {
			return math.Inf(-1)
		}
		return math.Inf(+1)
	case math.MinInt32:
		return math.NaN()
	}

	abs := func(x int) int {
		if x < 0 {
			return -x
		}
		return x
	}

	// Choose a precision high enough for *every* float64:
	//   – never less than 64 bits
	//   – plus extra to accommodate the scaling factor
	bitLen := mant.BitLen()
	scaler := map[int]int{2: 1, 8: 3, 10: 4}[base]
	prec := uint(bitLen + abs(exp)*scaler + 4)
	if prec < 64 {
		prec = 64
	}

	// High-precision multiply/divide without math.Pow
	bm := new(big.Float).SetPrec(prec).SetInt(mant)

	if exp != 0 {
		baseInt := big.NewInt(int64(base))
		powInt := new(big.Int).Exp(baseInt, big.NewInt(int64(abs(exp))), nil)
		be := new(big.Float).SetPrec(prec).SetInt(powInt)

		if exp > 0 {
			bm.Mul(bm, be) // mant · base^+exp
		} else {
			bm.Quo(bm, be) // mant / base^|exp|
		}
	}

	out, _ := bm.Float64()
	return out
}

func TestFloat64Components_roundTrip(t *testing.T) {
	type tuple struct {
		f    float64
		base int
	}
	var cases []tuple

	// finite numbers we want to round-trip exactly
	fin := []float64{
		0, -0, 1, -1,
		math.Pi, -math.E,
		123456.789, -98765.4321,
		math.SmallestNonzeroFloat64,
		math.MaxFloat64 / 2,
	}

	for _, f := range fin {
		for _, b := range []int{2, 8, 10} {
			cases = append(cases, tuple{f, b})
		}
	}

	for _, tc := range cases {
		m, e, err := float64Components(tc.f, tc.base)
		if err != nil {
			t.Fatalf("unexpected error for %v base %d: %v", tc.f, tc.base, err)
		}

		// mantissa must not be divisible by base (normalised) unless zero
		if tc.f != 0 && tc.base != 10 { // base-10 normalisation is trailing zeros
			b := big.NewInt(int64(tc.base))
			if new(big.Int).Mod(m, b).Sign() == 0 {
				t.Fatalf("mantissa %s still divisible by %d for %v", m, tc.base, tc.f)
			}
		}

		got := reconstruct(m, tc.base, e)
		if got != tc.f {
			t.Fatalf("round-trip failed: in=%g base=%d  out=%g (mant=%s exp=%d)",
				tc.f, tc.base, got, m.String(), e)
		}
	}
}

func TestFloat64Components_specials(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{math.Inf(+1), math.Inf(+1)},
		{math.Inf(-1), math.Inf(-1)},
		{math.NaN(), math.NaN()},
	}

	for _, tt := range tests {
		m, e, err := float64Components(tt.in, 2)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v", tt.in, err)
		}

		switch {
		case math.IsInf(tt.in, 0):
			if e != math.MaxInt32 || (tt.in > 0 && m.Sign() <= 0) || (tt.in < 0 && m.Sign() >= 0) {
				t.Fatalf("Inf mapping incorrect: mant=%s exp=%d", m, e)
			}
		case math.IsNaN(tt.in):
			if e != math.MinInt32 {
				t.Fatalf("NaN mapping incorrect: exp=%d", e)
			}
		}
	}
}

func TestFloat64Components_invalidBase(t *testing.T) {
	if _, _, err := float64Components(1.23, 17); err == nil {
		t.Fatalf("expected error for unsupported base, got nil")
	}
}

// sanity: mantissa is odd for base-2 path
func TestFloat64Components_base2OddMantissa(t *testing.T) {
	m, _, _ := float64Components(6.25, 2) // 6.25 = 25/4
	if m.BitLen() > 0 && bits.TrailingZeros64(m.Uint64()) != 0 {
		t.Fatalf("mantissa not odd: %s", m)
	}
}

func ExampleReal_withConstraints() {
	// Prohibit use of any base other than 2 or 8
	baseConstraint := LiftConstraint(func(o Real) Real { return o },
		func(o Real) (err error) {
			if o.Base != 2 && o.Base != 8 {
				err = fmt.Errorf("Constraint violation: prohibited base detected: %d", o.Base)
			}
			return
		})

	// Create a Real using base10.
	_, err := NewReal(314159, 10, -5, baseConstraint)
	fmt.Println(err)

	// Output:
	// Constraint violation: prohibited base detected: 10
}

func BenchmarkRealConstructor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewReal(314159, 10, -5); err != nil {
			b.Fatal(err)
		}
	}

}
