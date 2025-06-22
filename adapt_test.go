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

	if len(rawArgs) != 2 { // first arg + one constraint
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

func (_ temporalDummy) Cast() time.Time { return time.Now() }
func (_ temporalDummy) String() string  { return time.Now().String() }

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
