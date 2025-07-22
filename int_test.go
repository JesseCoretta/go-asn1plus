package asn1plus

import (
	"fmt"
	"math/big"
	"testing"
)

// Table of test cases.
var integerConstraintTests = []struct {
	name          string
	input         any
	expectFailure bool
	expectedValue int64
}{
	{
		name:          "Valid int within range",
		input:         50,
		expectFailure: false,
		expectedValue: 50,
	},
	{
		name:          "Int too low",
		input:         5,
		expectFailure: true,
	},
	{
		name:          "Int too high",
		input:         150,
		expectFailure: true,
	},
	{
		name:          "Valid string representing integer",
		input:         "75",
		expectFailure: false,
		expectedValue: 75,
	},
	{
		name:          "Invalid string value",
		input:         "abc",
		expectFailure: true,
	},
	{
		name:          "Already an Integer type",
		input:         Integer{big: false, native: 25},
		expectFailure: false,
		expectedValue: 25,
	},
	{
		name:          "Valid big.Int value",
		input:         big.NewInt(90),
		expectFailure: false,
		expectedValue: 90,
	},
	{
		name:          "Invalid big.Int value",
		input:         big.NewInt(150),
		expectFailure: true,
	},
}

func TestInteger_codecov(_ *testing.T) {
	for _, number := range []any{
		1,
		int32(1),
		int64(1),
		uint64(1),
		[]byte{0x5},
		uint64(9999897458392723342),
		`1`,
		`48329849320840239840328`,
		`-48329849320840239840328`,
		`432894892308499038249032840982304283049823894089239048239`,
		`-432894892308499038249032840982304283049823894089239048239`,
	} {
		for _, rule := range encodingRules {
			i, _ := NewInteger(number)
			_ = i.String()
			i.Big()
			i.IsBig()
			i.Bytes()
			i.Native()
			i.Eq(i)
			i.Lt(i)
			i.Le(i)
			i.Gt(i)
			i.Ge(i)
			i.Ne(i)
			der, _ := Marshal(i, With(rule))
			var i2 Integer
			_ = Unmarshal(der, &i2)
		}
	}

	_, _ = NewInteger(``)
	_, _ = NewInteger(struct{}{})
	encodeNativeInt(0)

	var i Integer = Integer{native: int64(4)}
	i.IsZero()
	i.IsPrimitive()
	i.Tag()
	_ = i.String()
	encodeNativeInt(3)
	decodeNativeInt([]byte{})
	bts := encodeNativeInt(-3)
	decodeNativeInt(bts)
	encodeIntegerContent(newBigInt(3))
	encodeIntegerContent(newBigInt(-3))

	ic := new(integerCodec[Integer])
	ic.encodeHook = func(b Integer) ([]byte, error) {
		return []byte{0x2, 0x1, 0x0}, nil
	}
	ic.decodeHook = func(b []byte) (Integer, error) {
		return Integer{native: int64(1)}, nil
	}
	ic.decodeVerify = []DecodeVerifier{func(b []byte) (err error) { return nil }}
	ic.Tag()
	ic.IsPrimitive()
	_ = ic.String()
	tpkt := &testPacket{}
	bpkt := &BERPacket{}
	_, _ = ic.write(tpkt, nil)
	_, _ = ic.write(bpkt, nil)
	ic.read(tpkt, TLV{}, nil)
	bpkt.data = []byte{0x1, 0x1, 0xFF, 0xFF}
	ic.read(tpkt, TLV{}, nil)
	ic.read(bpkt, TLV{}, nil)
	bcdIntegerRead(ic, bpkt, TLV{}, nil)

	if f, ok := master[refTypeOf(Integer{})]; ok {
		_ = f.newEmpty().(box)
		_ = f.newWith(Integer{}).(box)
	}

}

func TestInteger_Compare(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	x, _ := NewInteger(5)
	x.Eq(5)
	x.Eq(newBigInt(5))
	x.Eq([]byte{0x5})
	x.Eq(int64(5))
	x.Eq(int32(5))
	x.Eq(uint64(5))
	x.Eq(struct{}{})
}

// TestEncodeIntegerContent_Coverage tests every branch of encodeIntegerContent.
func TestEncodeIntegerContent_Coverage(t *testing.T) {
	// Table-driven tests.
	// For positive numbers, we specify the exact expected hex string.
	// For the "positive large" case, we simply perform a roundtrip check.
	// For negative numbers, we choose values that force:
	//   • n++ when i < -(1 << (8*n - 1))
	//   • A padding branch when the minimal byte slice is shorter than n.
	// Our expected outcomes (computed by DER minimal encoding rules) are as follows:
	tests := []struct {
		name    string
		in      string // input integer as a decimal string
		wantHex string // expected hex encoding; if empty, then perform roundtrip only.
	}{
		// Positive cases:
		{"Positive zero", "0", "00"},
		{"Positive small", "127", "7f"},
		{"Positive with MSB set", "128", "0080"},
		{"Positive large", "123456789", ""},
		// Negative cases:
		{"Negative needing n++ (-129)", "-129", "ff7f"},         // Forces n++ increase
		{"Negative needing padding (-256)", "-256", "ff00"},     // Forces zero-padding
		{"Negative needing prepend (-32768)", "-32768", "8000"}, // Forces extra 0xff prepend
		{"Negative one", "-1", "ff"},
		{"Negative with n++ triggered (-130)", "-130", "ff7e"},
		{"Negative with padding (-129)", "-129", "ff7f"},
		{"Negative forcing n=3 (-65281)", "-65281", "ff00ff"},
	}

	for _, tc := range tests {
		bi, ok := newBigInt(0).SetString(tc.in, 10)
		if !ok {
			t.Fatalf("%s: failed to parse integer %q", tc.name, tc.in)
		}
		got := encodeIntegerContent(bi)
		gotHex := hexstr(got)

		if tc.wantHex != "" {
			if gotHex != tc.wantHex {
				t.Errorf("%s: encodeIntegerContent(%s) = %s, want %s", tc.name, tc.in, gotHex, tc.wantHex)
			}
		} else {
			// For "Positive large", simply reassemble using big.Int and compare.
			redecoded := newBigInt(0).SetBytes(got)
			if redecoded.Cmp(bi) != 0 {
				t.Errorf("%s (roundtrip): got %s, want %s", tc.name, redecoded.String(), tc.in)
			}
		}

		// Additionally, perform a roundtrip for all cases.
		if bi.Sign() >= 0 {
			redecoded := newBigInt(0).SetBytes(got)
			if redecoded.Cmp(bi) != 0 {
				t.Errorf("%s (roundtrip): got %s, want %s", tc.name, redecoded.String(), tc.in)
			}
		} else {
			// For negative numbers, reverse the two's complement.
			nBytes := len(got)
			mod := newBigInt(0).Lsh(newBigInt(1), uint(8*nBytes))
			redecoded := newBigInt(0).SetBytes(got)
			redecoded.Sub(redecoded, mod)
			if redecoded.Cmp(bi) != 0 {
				t.Errorf("%s (roundtrip): got %s, want %s", tc.name, redecoded.String(), bi.String())
			}
		}
	}
}

// TestEncodeIntegerContent_NegativeBranches forces the uncovered branches in the negative section.
func TestEncodeIntegerContent_NegativeBranches(t *testing.T) {
	negCustom := newBigInt(0).SetBytes([]byte{0x7f})
	negCustom.Neg(negCustom)

	got := encodeIntegerContent(negCustom)
	if len(got) == 0 {
		t.Errorf("Custom negative: got empty result")
	} else if got[0]&0x80 == 0 {
		t.Errorf("Custom negative: expected first byte with MSB set, got %x", got[0])
	}

	testCases := []struct {
		name    string
		in      string
		wantHex string
	}{
		{"Negative needing n++ (-129)", "-129", "ff7f"},
		{"Negative minimal (-1)", "-1", "ff"},
	}

	for _, tc := range testCases {
		bi, ok := newBigInt(0).SetString(tc.in, 10)
		if !ok {
			t.Fatalf("%s: failed to parse integer %q", tc.name, tc.in)
		}
		enc := encodeIntegerContent(bi)
		hexEnc := hexstr(enc)
		if hexEnc != tc.wantHex {
			t.Errorf("%s: encodeIntegerContent(%s) = %s, want %s", tc.name, tc.in, hexEnc, tc.wantHex)
		}
		if bi.Sign() >= 0 {
			rd := newBigInt(0).SetBytes(enc)
			if rd.Cmp(bi) != 0 {
				t.Errorf("%s roundtrip: got %s, want %s", tc.name, rd.String(), bi.String())
			}
		} else {
			nBytes := len(enc)
			mod := newBigInt(0).Lsh(newBigInt(1), uint(8*nBytes))
			rd := newBigInt(0).SetBytes(enc)
			rd.Sub(rd, mod)
			if rd.Cmp(bi) != 0 {
				t.Errorf("%s roundtrip: got %s, want %s", tc.name, rd.String(), bi.String())
			}
		}
	}
}

func TestNewIntegerConstraints(t *testing.T) {
	// Define a custom constraint: the integer must be between 10 and 100 inclusive.
	allowedRange := func(x any) error {
		i, _ := NewInteger(x)
		var value int64
		if !i.big {
			value = i.native
		} else {
			// For simplicity, only handle *big.Int values that fit in int64.
			if i.bigInt.IsInt64() {
				value = i.bigInt.Int64()
			} else {
				return fmt.Errorf("integer too large for range check")
			}
		}
		if value < 10 || value > 100 {
			return fmt.Errorf("value %d not in range [10, 100]", value)
		}
		return nil
	}

	for _, tc := range integerConstraintTests {
		i, err := NewInteger(tc.input, allowedRange)
		if tc.expectFailure {
			if err == nil {
				t.Errorf("expected failure, but got integer: %+v", i)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			} else {
				// Check that the obtained integer equals the expected value.
				var val int64
				if !i.big {
					val = i.native
				} else {
					if i.bigInt.IsInt64() {
						val = i.bigInt.Int64()
					} else {
						t.Errorf("big integer does not fit in int64")
						return
					}
				}
				if val != tc.expectedValue {
					t.Errorf("expected value %d, got %d", tc.expectedValue, val)
				}
			}
		}
	}
}

type customInteger Integer

func (_ customInteger) Tag() int          { return TagInteger }
func (_ customInteger) String() string    { return `` }
func (_ customInteger) IsPrimitive() bool { return true }

func TestCustomInteger_withControls(t *testing.T) {
	orig, _ := NewInteger(123456)
	var cust customInteger = customInteger(orig) // cheat

	RegisterIntegerAlias[customInteger](TagInteger,
		IntegerConstraintPhase,
		func([]byte) error {
			return nil
		},
		func(customInteger) ([]byte, error) {
			return []byte{0x9, 0x5, 0xc1, 0x3, 0x12, 0xd6, 0x87}, nil
		},
		func([]byte) (customInteger, error) {
			return cust, nil
		},
		nil)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var next customInteger
	if err = Unmarshal(pkt, &next); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	unregisterType(refTypeOf(cust))
}

func BenchmarkIntegerConstructor(b *testing.B) {
	inty, _ := NewInteger(47676)
	for _, value := range []any{
		int64(1748),
		4378,
		-1,
		inty,
		"75849375689347598437983578495783548953947844759839784",
	} {
		for i := 0; i < b.N; i++ {
			if _, err := NewInteger(value); err != nil {
				b.Fatal(err)
			}
		}
	}
}
