package asn1plus

/*
err.go contains error constructors and literals used frequently.
throughout this package.
*/

import (
	"reflect"
	"sync"
)

var (
	errorAmbiguousChoice      error = mkerr("ambiguous alternative: multiple registered alternatives match the instance")
	errorNilInput             error = mkerr("nil or zero input instance")
	errorNilReceiver          error = mkerr("nil receiver instance")
	errorEmptyASN1Parameters  error = mkerr("ASN.1 parameters missing or truncated")
	errorEmptyIdentifier      error = mkerr("empty identifier")
	errorIndefiniteProhibited error = mkerr("Indefinite lengths not supported by encoding rule")
	errorDefaultNotFound      error = mkerr("defaultValue not found")
	errorNoDataAtOffset       error = mkerr("no data available at offset ")
	errorTruncDefLen          error = mkerr("definite length value truncated")
	errorBadLength            error = mkerr("error reading length")
)

/*
TLV errors.
*/
var (
	errorNegativeTLV       = tLVErr{mkerr("negative tag reached encoder")}
	errorNotExplicitTLV    = tLVErr{mkerr("expected constructed TLV for explicit tagging override")}
	errorNoEOCIndefTLV     = tLVErr{mkerr("missing end-of-contents for indefinite value")}
	errorDERNonMinLen      = tLVErr{mkerr("DER: non-minimal length encoding")}
	errorDERLeadingZeroLen = tLVErr{mkerr("DER: leading zero in length")}
	errorTruncBase128      = tLVErr{mkerr("truncated base-128 integer")}
	errorTruncTLV          = tLVErr{mkerr("truncated TLV")}
)

/*
choice errors.
*/
var (
	errorNoChoicesAvailable = choiceErr{mkerr("no alternatives registered")}
	errorNoChoiceForType    = choiceErr{mkerr("no matching alternative found")}
)

/*
PDU/codec errors.
*/
var (
	errorCodecNotFound      = codecErr{mkerr("codec not found")}
	errorNoEncodingRules    = codecErr{mkerr("no encoding rules loaded")}
	errorRuleNotImplemented = codecErr{mkerr("encoding rule not yet implemented or is deactivated")}
	errorLengthTooLarge     = codecErr{mkerr("length bytes too large (>4 octets)")}
	errorInvalidPacket      = codecErr{mkerr("invalid Packet instance")}
	errorEmptyLength        = codecErr{mkerr("length bytes not found")}
	errorTruncatedTag       = codecErr{mkerr("truncated high-tag-number form")}
	errorTruncatedContent   = codecErr{mkerr("packet content is truncated")}
	errorTruncatedLength    = codecErr{mkerr("packet length is truncated")}
	errorTagTooLarge        = codecErr{mkerr("tag too large (≥ 2^28)")}
	errorOutOfBounds        = codecErr{mkerr("content and offset out of bounds")}
)

/*
primitive errors
*/
var (
	errorMinOIDArcs    = primitiveErrorf("OBJECT IDENTIFIER: an OID must have two (2) or more number forms")
	errorMinRelOIDArcs = primitiveErrorf("RELATIVE-OID must have at least one arc")
	errorBadUTCTime    = primitiveErrorf("UTCTime is invalid")
	errorBadGT         = primitiveErrorf("GeneralizedTime is invalid")
)

/*
composite errors
*/
var (
	errorSeqEmptyNonOptField    = compositeErr{mkerr("SEQUENCE: missing required value for field")}
	errorComponentsNotAnonymous = compositeErr{mkerr("'COMPONENTS OF' requires field to be anonymous")}
)

/*
types which implement the error interface.
*/
type (
	adapterErr    struct{ e error }
	choiceErr     struct{ e error }
	codecErr      struct{ e error }
	compositeErr  struct{ e error }
	constraintErr struct{ e error }
	optionsErr    struct{ e error }
	primitiveErr  struct{ e error }
	tLVErr        struct{ e error }
)

func adapterErrorf(m ...any) error        { return adapterErr{mkerrf(m...)} }
func choiceErrorf(m ...any) error         { return choiceErr{mkerrf(m...)} }
func codecErrorf(m ...any) error          { return codecErr{mkerrf(m...)} }
func compositeErrorf(m ...any) error      { return compositeErr{mkerrf(m...)} }
func constraintViolationf(m ...any) error { return constraintErr{mkerrf(m...)} }
func optionsErrorf(m ...any) error        { return optionsErr{mkerrf(m...)} }
func primitiveErrorf(m ...any) error      { return primitiveErr{mkerrf(m...)} }
func tLVErrorf(m ...any) error            { return tLVErr{mkerrf(m...)} }

func (r adapterErr) Error() string    { return `ADAPTER ERROR: ` + r.e.Error() }
func (r choiceErr) Error() string     { return `CHOICE ERROR: ` + r.e.Error() }
func (r codecErr) Error() string      { return `CODEC ERROR: ` + r.e.Error() }
func (r compositeErr) Error() string  { return `COMPOSITE ERROR: ` + r.e.Error() }
func (r constraintErr) Error() string { return `CONSTRAINT VIOLATION: ` + r.e.Error() }
func (r optionsErr) Error() string    { return `OPTIONS ERROR: ` + r.e.Error() }
func (r primitiveErr) Error() string  { return `PRIMITIVE ERROR: ` + r.e.Error() }
func (r tLVErr) Error() string        { return `TLV ERROR: ` + r.e.Error() }

func errorNamedDefaultNotFound(name string) (err error) {
	if len(name) == 0 {
		name = "unknown default"
	}
	err = mkerrf(errorDefaultNotFound.Error(), ": ", name)
	return
}

func errorUnknownConstraint(n string) error {
	return constraintErr{mkerr("unknown or unregistered constraint: " + n)}
}

func errorBadTypeForConstructor(asn1Type string, inputType any) (err error) {
	var inName string = "<nil>" // sensible default
	if inputType != nil {
		inName = refTypeOf(inputType).String()
	}
	return primitiveErrorf("Invalid input type for ASN.1 ",
		asn1Type, " constructor: ", inName)
}

func errorNoChoiceMatched(name string) (err error) {
	return choiceErrorf(errorNoChoiceForType.Error() + " " + name)
}

func errorNullLengthNonZero(length int) (err error) {
	if length > 0 {
		err = mkerrf("NULL: content length must be 0, got ", itoa(length))
	}

	return
}

func errorTLVNoData(r PDU) (err error) {
	off := r.Offset()
	ln := r.Len()
	if off >= ln {
		length := ` (len:` + itoa(ln) + `)`
		typ := r.Type().String() + "TLV: "
		err = tLVErr{mkerrf(typ, errorNoDataAtOffset, off, length)}
	}
	return
}

func errorASN1Expect(a, b any, typ string) (err error) {
	switch typ {
	case "Tag":
		i, j := a.(int), b.(int)
		err = mkerrf("Expect" + typ + ": wrong tag: got " + itoa(j) + " (" +
			TagNames[j] + "), want " + itoa(i) + " (" + TagNames[i] + ")")
	case "Class":
		i, j := a.(int), b.(int)
		err = mkerrf("Expect" + typ + ": wrong class: got " + itoa(j) + " (" +
			ClassNames[j] + "), want " + itoa(i) + " (" + ClassNames[i] + ")")
	case "Length":
		i, j := a.(int), b.(int)
		err = mkerrf("Expect" + typ + ": wrong length: got " + itoa(j) + ", want " + itoa(i))
	case "Compound":
		i, j := a.(bool), b.(bool)
		err = mkerrf("Expect" + typ + ": wrong compound: got " + bool2str(j) + " (" +
			CompoundNames[j] + "), want " + bool2str(i) + " (" + CompoundNames[i] + ")")
	}

	return
}

func errorASN1TagInClass(expectClass, expectTag, class, tag int) (err error) {
	if class != expectClass || tag != expectTag {
		err = mkerrf("expected tag " + TagNames[expectTag] + " in class " +
			ClassNames[expectClass] + ", got tag " + itoa(tag) +
			" in class " + itoa(class))
	}

	return
}

func errorASN1ConstructedTagClass(wantTLV, gotTLV TLV) error {
	return mkerrf("Constructed: expected compound element with class " + itoa(wantTLV.Class) +
		" and tag " + itoa(wantTLV.Tag) + ", got class " + itoa(gotTLV.Class) + " and tag " + itoa(gotTLV.Tag) +
		", compound:" + bool2str(gotTLV.Compound))
}

var errCache sync.Map

func mkerrf(parts ...any) error {
	if len(parts) == 1 {
		if s, ok := parts[0].(string); ok {
			if v, hit := errCache.Load(s); hit {
				return v.(error)
			}
		}
	}

	b := newStrBuilder()
	for _, p := range parts {
		switch v := p.(type) {
		case TLV:
			b.WriteString(v.String())
		case EncodingRule:
			b.WriteString(v.String())
		case error:
			b.WriteString(v.Error())
		case string:
			b.WriteString(v)
		case reflect.Type:
			b.WriteString(v.String())
		case int:
			b.WriteString(itoa(v))
		default:
			b.WriteString("<not supported>")
		}
	}
	msg := b.String()

	if v, hit := errCache.Load(msg); hit {
		return v.(error)
	}
	e := mkerr(msg)
	errCache.Store(msg, e)
	return e
}
