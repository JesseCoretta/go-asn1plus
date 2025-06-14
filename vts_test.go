package asn1plus

import "testing"

func TestVideotexString_encodingRules(t *testing.T) {
	for idx, value := range []any{
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
			vts, err := NewVideotexString(value)
			if err != nil {
				t.Fatalf("%s[%d] failed [%s NewVideotexString]: %v",
					t.Name(), idx, rule, err)
			}

			var pkt Packet
			if pkt, err = Marshal(vts); err != nil {
				t.Fatalf("%s[%d] failed [%s encoding]: %v",
					t.Name(), idx, rule, err)
			}

			var vts2 VideotexString
			if err = Unmarshal(pkt, &vts2); err != nil {
				t.Fatalf("%s[%d] failed [%s decoding]: %v",
					t.Name(), idx, rule, err)
			}

			vts1Str := vts.String()
			vts2Str := vts2.String()

			if vts1Str != vts2Str {
				t.Fatalf("%s[%d] failed [%s string cmp.]\n\twant: '%s'\n\tgot:  '%s'",
					t.Name(), idx, rule, vts1Str, vts2Str)
			}
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
	vts.read(nil, TLV{}, Options{})
	vts.read(&BERPacket{}, TLV{}, Options{})
}
