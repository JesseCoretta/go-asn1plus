//go:build asn1_debug

package asn1plus

import "testing"

func TestLoglevels_codecov(t *testing.T) {
	var bits loglevels
	bits.Int()
	bits.Shift(-1)
	bits.Shift(8 << 8)
	bits.Unshift(-1)
	bits.Positive(-1)
	bits.Unshift(40000000000)
	if i := bits.Int(); i != 0 {
		t.Errorf("%s failed: bogus value set (%d) where none should be",
			t.Name(), i)
	}

	bits = newLoglevels()
	bits.Shift(bits.Max())
	bits.Shift(8 << 8)
	bits.Shift(8 << 1)
	bits.Positive(8 << 2)
	bits.Unshift(8 << 8)
	bits.Int()

	bld := newStrBuilder()
	dt := NewDefaultTracer(&bld)
	dt.Trace(TraceRecord{
		Type: EventEnter,
		Args: []any{1, 2, 3},
	})
	dt.EnableLevel(0)
	dt.EnableLevel(1)
	dt.EnableLevel(2)
	dt.EnableLevel(4)
	dt.EnableLevel(8)
	dt.DisableLevel(0)

	debugPath("")

	var disc *discardTracer
	disc.Trace(TraceRecord{})

	dt.Trace(TraceRecord{
		Type: EventEnter,
		Args: []any{1, 2, 3},
	})
	dt.Trace(TraceRecord{
		Type: EventInfo,
		Args: []any{1, 2, 3},
	})
	dt.Trace(TraceRecord{
		Type: EventExit,
		Ret:  []any{1, 2, 3},
	})

	dt.ll.NamesMap()
	dt.ll.SetNamesMap(map[int]string{
		1: "one",
	})
	dt.ll.unshiftExtremes(1)
	dt.ll.strIndex("one")
	dt.ll.strIndex("two")
	dt.ll.None()
	dt.ll.All()
	dt.ll.verifyShiftValue("one")
	toLogInt("z")
	toLogInt(1)
	toLogInt(uint8(1))
	toLogInt(uint16(1))

	fmtDefaultArg(rune(33))

	for _, val := range []any{
		"1",
		1,
		true,
		[]byte{0x1, 0x2},
		newLItem(nil),
		struct{}{},
		[]struct{}{},
		&Options{},
		Options{},
		&BERPacket{},
		&BERPacket{data: []byte{0x4, 0x1, 0x5, 0x8}},
		BER,
		refTypeOf("1"),
		refValueOf("1"),
		TLV{},
		OctetString("1"),
		new(textCodec[OctetString]),
	} {
		fmtArg(val)
	}
}
