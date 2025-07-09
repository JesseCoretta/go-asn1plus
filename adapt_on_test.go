//go:build !asn1_no_adapter_pf

package asn1plus

import (
	"fmt"
	"testing"
	"time"
)

func TestDuration_customType(t *testing.T) {
	type CustomDur Duration
	RegisterDurationAlias[CustomDur](TagDuration,
		DurationConstraintPhase,
		nil, nil, nil, nil)

	// We cheat here rather than writing a separate
	// constructor merely for testing.
	orig, _ := NewDuration(time.Duration(time.Second * 50))
	cust := CustomDur(orig)

	pkt, err := Marshal(cust, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}

	var out CustomDur
	if err = Unmarshal(pkt, &out); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	// We cheat again, since we didn't write a
	// custom OID method for this simple test.
	cast1 := Duration(orig).String()
	cast2 := Duration(cust).String()
	if cast1 != cast2 {
		t.Fatalf("%s failed [BER Duration cmp.]:\n\twant: %s\n\tgot:  %s",
			t.Name(), cast1, cast2)
	}
}

func TestBitString_customType(t *testing.T) {
	type CustomBits BitString
	RegisterBitStringAlias[CustomBits](TagBitString,
		BitStringConstraintPhase,
		nil, nil, nil, nil)

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

/*
This example demonstrates encoding and decoding an ASN.1 DATE
(2021-09-18) to/from a simple Go string.

	1F 1F  0A  32 30 32 31 2D 30 39 2D 31 38
	│  │   │   └─────────────── "2021-09-18" ───────────────┘
	│  │   └── length = 10
	└──┴────────── tag = UNIVERSAL 31 (DATE)
*/
func ExampleDate_viaGoString() {
	opts := Options{Identifier: "date"}

	pkt, err := Marshal(`2021-09-18`,
		With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("PDU hex: %s\n", pkt.Hex())

	var date string
	if err = Unmarshal(pkt, &date, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Date: %s\n", date)

	// Output:
	// PDU hex: 1F1F 0A 323032312D30392D3138
	// Date: 2021-09-18
}

func ExampleTimeOfDay_viaGoString() {
	opts := Options{Identifier: "time-of-day"}

	pkt, err := Marshal(`15:32:01`, With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("PDU hex: %s\n", pkt.Hex())

	var tod string
	if err = Unmarshal(pkt, &tod, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Time: %s\n", tod)

	// Output:
	// PDU hex: 1F20 08 31353A33323A3031
	// Time: 15:32:01
}

func ExampleTime_viaGoString() {
	opts := Options{Identifier: "time"}

	pkt, err := Marshal(`2018-09-11T15:32:01`, With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("PDU hex: %s\n", pkt.Hex())

	var thyme string
	if err = Unmarshal(pkt, &thyme, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Time: %s\n", thyme)

	// Output:
	// PDU hex: 0E 13 323031382D30392D31315431353A33323A3031
	// Time: 2018-09-11T15:32:01
}

func ExampleObjectIdentifier_viaGoString() {
	opts := Options{Identifier: "oid"}
	pkt, err := Marshal("1.3.6.1.4.1.56521",
		With(BER, opts))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Jesse's encoded OID: %s\n", pkt.Hex())

	var oid string
	if err = Unmarshal(pkt, &oid, With(opts)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Jesse's decoded OID: %s", oid)
	// Output:
	// Jesse's encoded OID: 06 08 2B0601040183B949
	// Jesse's decoded OID: 1.3.6.1.4.1.56521
}

func ExampleObjectIdentifier_sequenceWithStringOID() {
	type MySequence struct {
		Name string `asn1:"descriptor"`
		OID  string `asn1:"oid"`
	}

	mine := MySequence{"Jesse Coretta", "1.3.6.1.4.1.56521"}

	pkt, err := Marshal(mine, With(BER))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Encoded sequence: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded sequence: %s, %s", mine2.Name, mine2.OID)
	// Output:
	// Encoded sequence: 30 19 070D4A6573736520436F726574746106082B0601040183B949
	// Decoded sequence: Jesse Coretta, 1.3.6.1.4.1.56521
}

func ExampleBoolean_viaGoBool() {
	pkt, err := Marshal(true, With(BER))

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Boolean encoding: %s\n", pkt.Hex())

	var b bool
	if err = Unmarshal(pkt, &b); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Boolean: %t", b)
	// Output:
	// Boolean encoding: 01 01 FF
	// Boolean: true
}

func ExampleOctetString_viaGoStringWithTaggedConstraint() {
	// Prohibit use of any digit characters
	digitConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if '0' <= rune(o[i]) && rune(o[i]) <= '9' {
					err = fmt.Errorf("Constraint violation: policy prohibits digits")
					break
				}
			}
			return
		})

	// Prohibit any lower-case ASCII letters
	caseConstraint := LiftConstraint(func(o OctetString) OctetString { return o },
		func(o OctetString) (err error) {
			for i := 0; i < len(o); i++ {
				if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
					err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
					break
				}
			}
			return
		})

	// Create a single constraint group and register it
	// as a tagged function. We can put as many constraint
	// functions in a group as we please.
	RegisterTaggedConstraintGroup("octetStringConstraints", ConstraintGroup[OctetString]{
		digitConstraint,
		caseConstraint,
	})

	var options Options = Options{
		Identifier:  "octet",
		Constraints: []string{`octetStringConstraints`},
	}

	pkt, err := Marshal(`test48`,
		With(BER, options))

	// We violated to the "no digits" policy.
	if err != nil {
		fmt.Println(err)
	}

	// Lets try again
	pkt, err = Marshal(`test`,
		With(BER, options))

	// We passed the "no digits" policy, but violated
	// the "no lower case" policy.
	if err != nil {
		fmt.Println(err)
	}

	pkt, err = Marshal(`TEST`,
		With(BER, options))

	// Third time's a charm?
	if err != nil {
		fmt.Println(err)
		return
	}

	// We passed all constraints.

	fmt.Printf("Encoded value: %s\n", pkt.Hex())

	var out string
	if err = Unmarshal(pkt, &out, With(options)); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded value: %s", out)
	// Output:
	// Constraint violation: policy prohibits digits
	// Constraint violation: policy prohibits lower-case ASCII
	// Encoded value: 04 04 54455354
	// Decoded value: TEST
}

func TestWrapOIDCtor(t *testing.T) {
	var (
		rawArgs    []any
		rawInvoked bool
	)

	raw := func(a ...any) (ObjectIdentifier, error) {
		rawInvoked = true
		rawArgs = a

		// a[1] should be the forwarded constraint; call it to prove
		// that wrapOIDCtor delivered it intact.
		if c, ok := a[1].(Constraint[ObjectIdentifier]); ok {
			_ = c(ObjectIdentifier{}) // ignore error, flip flag
		}

		return testMust(NewObjectIdentifier("1.2.3")), nil
	}

	oidConv := wrapOIDCtor[string](raw, func(s string) any { return s })

	var constraintHit bool
	cons := testMakeConstraint[ObjectIdentifier](&constraintHit)

	oid, err := oidConv("1.2.840", cons)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !rawInvoked {
		t.Fatalf("raw constructor was not invoked")
	}
	if !constraintHit {
		t.Fatalf("constraint was not forwarded to raw constructor")
	}

	want := testMust(NewObjectIdentifier(1, 2, 3))
	if !deepEq(oid, want) {
		t.Fatalf("returned OID mismatch: got %v want %v", oid, want)
	}

	if len(rawArgs) != 2 {
		// first arg + one constraint
		t.Fatalf("raw received %d args, want 2", len(rawArgs))
	}
	if rawArgs[0] != "1.2.840" {
		t.Fatalf("first arg %v, want 1.2.840", rawArgs[0])
	}
}

func TestWrapRelOIDCtor(t *testing.T) {
	var (
		rawInvoked bool
		gotFirst   any
		csForward  bool
	)

	raw := func(a ...any) (RelativeOID, error) {
		rawInvoked = true
		gotFirst = a[0]
		a[1].(Constraint[RelativeOID])(RelativeOID{})
		return NewRelativeOID(1, 3, 6)
	}

	wrapper := wrapRelOIDCtor[int](raw, func(i int) any { return i })

	_, err := wrapper(42, func(_ RelativeOID) error { csForward = true; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rawInvoked || gotFirst != 42 || !csForward {
		t.Fatalf("wrapper did not forward parameters correctly")
	}
}

type temporalDummy struct{ time.Time }

func (_ temporalDummy) Cast() time.Time    { return tnow() }
func (_ temporalDummy) String() string     { return tnow().String() }
func (_ temporalDummy) Eq(_ Temporal) bool { return false }
func (_ temporalDummy) Ne(_ Temporal) bool { return false }
func (_ temporalDummy) Gt(_ Temporal) bool { return false }
func (_ temporalDummy) Ge(_ Temporal) bool { return false }
func (_ temporalDummy) Lt(_ Temporal) bool { return false }
func (_ temporalDummy) Le(_ Temporal) bool { return false }

func TestWrapTemporalCtor(t *testing.T) {
	var (
		gotTime   time.Time
		csTouched bool
	)

	raw := func(x any, cs ...Constraint[Temporal]) (temporalDummy, error) {
		gotTime = x.(time.Time)
		cs[0](temporalDummy{})
		return temporalDummy{}, nil
	}

	wrapped := wrapTemporalCtor[temporalDummy](raw)

	now := tnow()
	_, err := wrapped(now, func(_ temporalDummy) error { csTouched = true; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotTime.Equal(now) || !csTouched {
		t.Fatalf("temporal wrapper failed to forward parameters/constraints")
	}
}

func TestRealCtor(_ *testing.T) {
	r := wrapRealCtor[float64](2, func(float64, int) (any, int, error) { return nil, 0, nil })
	r(float64(9.2))

	r2 := wrapTemporalStringCtor[Time](
		func(any, ...Constraint[Temporal]) (Time, error) { return Time{}, nil },
		func(string) (time.Time, error) { return time.Time{}, nil },
	)
	r2(time.Now().String(), func(Time) error { return nil })
}

func TestAdapterPF_codecov(_ *testing.T) {
	var opts *Options = &Options{}
	var pkt PDU
	for _, iter := range []struct {
		ident string
		input any
	}{
		{
			ident: "utf8",
			input: "this is UTF-8",
		},
		{
			ident: "numeric",
			input: "09 72834 990",
		},
		{
			ident: "visible",
			input: "can you see me?",
		},
		{
			ident: "videotex",
			input: "don't mess with textas",
		},
		{
			ident: "general",
			input: "Brigadier General Jack O'Neill", // TWO L's!
		},
		{
			ident: "t61",
			input: "also known as teletex",
		},
		{
			ident: "graphic",
			input: "viewer discretion advised",
		},
		{
			ident: "ia5",
			input: "International Alphabet No. 5",
		},
		{
			ident: "bmp",
			input: "BMP strings are fat",
		},
		{
			ident: "universal",
			input: "Universal strings are morbidly obese",
		},
		{
			ident: "octet",
			input: "Octet strings have tentacles",
		},
		{
			ident: "octet",
			input: []byte("Octet strings have tentacles"),
		},
		{
			ident: "bitstring",
			input: []byte{0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x1},
		},
	} {
		opts.Identifier = iter.ident
		pkt, _ = Marshal(iter.input, With(opts))
		var strVal string
		_ = Unmarshal(pkt, &strVal, With(opts))
	}

	opts.Identifier = "enum"
	pkt, _ = Marshal(3, With(opts))
	var enumer int
	_ = Unmarshal(pkt, &enumer, With(opts))

	opts.Identifier = "integer"
	pkt, _ = Marshal(3, With(opts))
	var inter int
	_ = Unmarshal(pkt, &inter, With(opts))

	opts.Identifier = "duration"
	pkt, _ = Marshal(int64(43872), With(opts))
	var durer1 int
	_ = Unmarshal(pkt, &durer1, With(opts))

	pkt, _ = Marshal(time.Duration(43872), With(opts))
	var durer2 time.Duration
	_ = Unmarshal(pkt, &durer2, With(opts))

	pkt, _ = Marshal("34728957329", With(opts))
	var durer3 string
	_ = Unmarshal(pkt, &durer3, With(opts))

}
