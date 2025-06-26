package asn1plus

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// stubPrimitive satisfies the Primitive interface but does nothing.
// Only the pointer form (*stubPrimitive) needs to implement the methods
// used by chainAdapters’ callers.
type stubPrimitive struct{}

func (p stubPrimitive) String() string    { return `` }
func (p stubPrimitive) Tag() int          { return 999 }
func (p stubPrimitive) IsPrimitive() bool { return true }

// helper that returns an adapter whose fromGo either fails or succeeds.
func testMakeAdapter(shouldSucceed bool) adapter {
	return adapter{
		// newCodec / toGo are irrelevant for this test
		fromGo: func(_ any, _ Primitive, _ *Options) error {
			if shouldSucceed {
				return nil
			}
			return mkerr("fail")
		},
	}
}

func TestChainAdapters(t *testing.T) {
	pr := &stubPrimitive{}
	opts := &Options{}

	// Case 1: first adapter fails, second succeeds
	ad := chainAdapters([]adapter{
		testMakeAdapter(false), // will return error
		testMakeAdapter(true),  // will succeed
	})

	if err := ad.fromGo("dummy", pr, opts); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// Case 2: all adapters fail
	adAllFail := chainAdapters([]adapter{
		testMakeAdapter(false),
		testMakeAdapter(false),
	})

	if err := adAllFail.fromGo("dummy", pr, opts); err == nil {
		t.Fatalf("expected error when all adapters fail, got nil")
	}
}

/*
This example demonstrates how an application can discover the set of
adapters that are currently registered.

For deterministic output we first register a private keyword ("example")
and then print only that entry from the returned slice.
*/
func ExampleListAdapters() {
	// 1. Register a throw-away keyword so we know exactly what to expect.
	RegisterAdapter[UTF8String, string](
		func(s string, cs ...Constraint[UTF8String]) (UTF8String, error) {
			return NewUTF8String(s, cs...)
		},
		func(p *UTF8String) string { return string(*p) },
		"example",
	)

	// 2. Enumerate and filter for that keyword.
	for _, ai := range ListAdapters() {
		if ai.Keyword == "example" {
			fmt.Printf("%s: %s  (keyword %q)\n", ai.GoType, ai.Primitive, ai.Keyword)
		}
	}

	// Output:
	// string: asn1plus.textCodec[github.com/JesseCoretta/go-asn1plus.UTF8String]  (keyword "example")
}

func testMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// dummy constraints just flip a flag when invoked
func testMakeConstraint[T any](hit *bool) Constraint[T] {
	return func(_ T) error { *hit = true; return nil }
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
	if !reflect.DeepEqual(oid, want) {
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

func (_ temporalDummy) Cast() time.Time    { return time.Now() }
func (_ temporalDummy) String() string     { return time.Now().String() }
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

	now := time.Now()
	_, err := wrapped(now, func(_ temporalDummy) error { csTouched = true; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotTime.Equal(now) || !csTouched {
		t.Fatalf("temporal wrapper failed to forward parameters/constraints")
	}
}

func TestAdapter_ValueOfShouldPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: expected panic but function did not panic", t.Name())
		}
	}()

	value := "badIdea"
	wrapped := &value
	badIdea := &wrapped
	valueOf[string](badIdea)
}

func TestAdapter_codecov(_ *testing.T) {
	RegisterAdapter[stubPrimitive, string](nil, func(*stubPrimitive) string { return `` }, "bogusCodec")
	var stubby stubPrimitive
	opts := &Options{Identifier: "bogusCodec"}
	pkt, _ := Marshal(stubby, With(opts))
	var stubbs stubPrimitive
	_ = Unmarshal(pkt, &stubbs, With(opts))
	opts.Identifier = "brogusCodec"
	pkt, _ = Marshal(stubby, With(opts))
	_ = Unmarshal(pkt, &stubbs, With(opts))
	unregisterType(refTypeOf(stubby))

	r := wrapRealCtor[float64](2, func(float64, int) (any, int, error) { return nil, 0, nil })
	r(float64(9.2))

	r2 := wrapTemporalStringCtor[Time](
		func(any, ...Constraint[Temporal]) (Time, error) { return Time{}, nil },
		func(string) (time.Time, error) { return time.Time{}, nil },
	)
	r2(time.Now().String(), func(Time) error { return nil })

	// misc. textCodec coverage
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
