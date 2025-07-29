//go:build !asn1_debug

package asn1plus

import "testing"

func TestLoglevels_codecov(t *testing.T) {
	var bits loglevels
	bits.Int()
	bits.Shift(-1)
	bits.Max()
	bits.Min()
	bits.All()
	bits.None()
	bits.NamesMap()
	bits.SetNamesMap(nil)
	bits.shift(1)
	bits.isExtreme(1)
	bits.shiftExtremes(1)
	bits.unshift(1)
	bits.verifyShiftValue(1)
	bits.strIndex("test")
	bits.positive(1)
	bits.unshiftExtremes(1)
	bits.enabled()
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

	debugPath("")
	debugInfo()
	debugIO()
	debugPDU()
	debugConstraint()
	debugPerf()
	debugComposite()

	li := labeledItem{}
	_ = li.String()

	toLogInt("z")
	toLogInt(1)
	toLogInt(uint8(1))
	toLogInt(uint16(1))
}
