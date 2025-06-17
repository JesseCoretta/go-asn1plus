package asn1plus

/*
err.go contains error constructors and literals used frequently.
throughout this package.
*/

import "sync"

var (
	errorAmbiguousChoice       error = mkerr("ambiguous alternative: multiple registered alternatives match the instance")
	errorNoChoicesAvailable    error = mkerr("no CHOICE alternatives available")
	errorNoChoiceForType       error = mkerr("no matching alternative found for input type")
	errorNilInput              error = mkerr("nil input instance")
	errorNilReceiver           error = mkerr("nil receiver instance")
	errorNoPrimitiveRead       error = mkerr("type does not implement read method")
	errorNoCompoundChoices     error = mkerr("no compound CHOICE alternatives available")
	errorNoCompoundChoiceMatch error = mkerr("no compound CHOICE alternatives matched the data")
	errorEmptyASN1Parameters   error = mkerr("ASN.1 parameters missing or truncated")
	errorEmptyIdentifier       error = mkerr("empty identifier")
	errorTagTooLarge           error = mkerr("tag too large (≥ 2^28)")
	errorTruncatedTag          error = mkerr("truncated high-tag-number form")
	errorOutOfBounds           error = mkerr("content and offset out of bounds")
	errorIndefiniteProhibited  error = mkerr("Indefinite lengths not supported by encoding rule")
	errorInvalidPacket         error = mkerr("invalid Packet instance")
	errorEmptyLength           error = mkerr("length bytes not found")
	errorTruncatedContent      error = mkerr("packet content is truncated")
	errorTruncatedLength       error = mkerr("packet length is truncated")
	errorLengthTooLarge        error = mkerr("length bytes too large (>4 octets)")
)

func errorNoChoiceMatched(name string) (err error) {
	return mkerrf(errorNoChoiceForType.Error() + " " + name)
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
		case string:
			b.WriteString(v)
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
