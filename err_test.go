package asn1plus

import (
	"testing"
)

func TestExpectError(t *testing.T) {
	_ = errorASN1Expect(1, 2, "Tag")
	_ = errorASN1Expect(1, 2, "Class")
	_ = errorASN1Expect(1, 2, "Length")
	_ = errorASN1Expect(true, false, "Compound")

	_ = errorASN1TagInClass(2, 1, 3, 4)
	_ = errorASN1ConstructedTagClass(
		TLV{Class: 2, Tag: 1, Compound: true, Length: 15},
		TLV{Class: 2, Tag: 1, Compound: false, Length: 15},
	)

	_ = mkerrf("Hello ", 5)
	_ = mkerrf("Hello ", struct{}{})
}
