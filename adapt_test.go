package asn1plus

import (
	"fmt"
	"testing"
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
			return adapterErrorf("fail")
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
		func(s string, cs ...Constraint) (UTF8String, error) {
			return NewUTF8String(s, cs...)
		},
		func(p *UTF8String) string { return string(*p) },
		"example",
	)

	// 2. Enumerate and filter for that keyword.
	for _, ai := range ListAdapters() {
		if ai.Keyword == "example" {
			fmt.Printf("%s: %s  (keyword %q)\n",
				ai.GoType, ai.Primitive, ai.Keyword)
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
func testMakeConstraint[T any](hit *bool) Constraint {
	return func(_ any) error { *hit = true; return nil }
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
	UnregisterAdapter[stubPrimitive, string]()
	unregisterType(refTypeOf(stubby))
}
