package asn1plus

import (
	"testing"
)

func TestExpectError(t *testing.T) {
	choiceErrorf("blarg")
	tLVErrorf("blarg")
	var nonNilErr error = mkerr("test")
	nonNilErr = adapterErr{nonNilErr}
	_ = nonNilErr.Error()
	nonNilErr = choiceErr{nonNilErr}
	_ = nonNilErr.Error()
	nonNilErr = primitiveErr{nonNilErr}
	_ = nonNilErr.Error()

	errorNamedDefaultNotFound(``)
	_ = errorUnknownConstraint(`test`)
	mkerrf()
	mkerrf(nil)
}
