//go:build !asn1_no_dprc

package asn1plus

import (
	"fmt"
	"testing"
)

func TestMustNewVideotexString_MustPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), errorNoPanic)
		}
	}()
	_ = MustNewVideotexString(struct{}{})
}

func TestVideotexString_encodingRules(t *testing.T) {
	for _, value := range []any{
		// Simple ASCII
		"A simple VIDEOTEX string!",
		[]byte("A simple VIDEOTEX string!"),
		VideotexString("A simple VIDEOTEX string!"),

		// Spanish with inverted punctuation
		"¡Hola, mundo!",
		[]byte("¡Hola, mundo!"),
		VideotexString("¡Hola, mundo!"),

		// Extended Latin characters
		"Naïve façade: résumé, coöperate.",
		[]byte("Naïve façade: résumé, coöperate."),
		VideotexString("Naïve façade: résumé, coöperate."),

		// Box drawing characters (T.101)
		"Box: ─┼─┐",
		[]byte("Box: ─┼─┐"),
		VideotexString("Box: ─┼─┐"),

		// Mosaic/block elements
		"Mosaic: █▀▄▌▐",
		[]byte("Mosaic: █▀▄▌▐"),
		VideotexString("Mosaic: █▀▄▌▐"),

		// Geometric shapes and miscellaneous symbols
		"Symbols: ▲▼◆◇♪♫",
		[]byte("Symbols: ▲▼◆◇♪♫"),
		VideotexString("Symbols: ▲▼◆◇♪♫"),

		// CJK (Chinese)
		"中文测试",
		[]byte("中文测试"),
		VideotexString("中文测试"),

		// Arabic
		"مرحبا بالعالم",
		[]byte("مرحبا بالعالم"),
		VideotexString("مرحبا بالعالم"),

		// Cyrillic
		"Привет, мир!",
		[]byte("Привет, мир!"),
		VideotexString("Привет, мир!"),

		// Greek
		"Γειά σου Κόσμε",
		[]byte("Γειά σου Κόσμε"),
		VideotexString("Γειά σου Κόσμε"),

		// Hebrew
		"שלום עולם",
		[]byte("שלום עולם"),
		VideotexString("שלום עולם"),

		// Mixed exotic characters from several scripts
		"Mixed: ¡Hola!, Привет, 你好, and مرحبا!",
		[]byte("Mixed: ¡Hola!, Привет, 你好, and مرحبا!"),
		VideotexString("Mixed: ¡Hola!, Привет, 你好, and مرحبا!"),
	} {
		for _, rule := range encodingRules {
			//t.Parallel() // optional

			//start := time.Now()
			vts, err := NewVideotexString(value)
			if err != nil {
				t.Fatalf("%s NewVideotexString error: %v", t.Name(), err)
			}
			pkt, err := Marshal(vts, With(rule))
			if err != nil {
				t.Fatalf("%s Marshal(%s) error: %v", t.Name(), rule.String(), err)
			}

			var vts2 VideotexString
			if err := Unmarshal(pkt, &vts2); err != nil {
				t.Fatalf("%s Unmarshal(%s) error: %v", t.Name(), rule.String(), err)
			}

			got, want := vts2.String(), vts.String()
			if got != want {
				t.Fatalf("%s round-trip mismatch for %s:\n\twant=%q\n\t got=%q",
					t.Name(), rule.String(), want, got)
			}

			//elapsed := time.Since(start)
			//t.Logf("%s took %s", name, elapsed)
		}
	}
}

func BenchmarkVideotexConstructor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewVideotexString("hello videótex"); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleVideotexString_withConstraint() {
	caseConstraint := func(x any) (err error) {
		o, _ := x.(VideotexString)
		for i := 0; i < len(o); i++ {
			if 'a' <= rune(o[i]) && rune(o[i]) <= 'z' {
				err = fmt.Errorf("Constraint violation: policy prohibits lower-case ASCII")
				break
			}
		}
		return
	}

	_, err := NewVideotexString(`this is a VIDEOTEX STRING`, caseConstraint)
	fmt.Println(err)
	// Output: Constraint violation: policy prohibits lower-case ASCII
}

func TestVideotexString_codecov(_ *testing.T) {
	_, _ = NewVideotexString(struct{}{})
	_, _ = NewVideotexString(string([]rune{
		0xFFFFF,
		0x20AC,
		0x2014,
		0x2026,
		0x1F431,
		0x00DF,
		0x03BB,
		0x6771,
		0x0080,
	}))
	var vts VideotexString
	vts.Len()
	vts.Tag()
	vts.IsZero()
	vts.IsPrimitive()

	VideotexSpec([]byte{0x1, 0x2, 0x3})
	VideotexSpec(`test`)
	VideotexSpec(struct{}{})

	badRune := uint32(0xD800)

	b := []byte{
		byte(badRune >> 24),
		byte(badRune >> 16),
		byte(badRune >> 8),
		byte(badRune),
	}

	videotexDecoderVerify(b)
}
