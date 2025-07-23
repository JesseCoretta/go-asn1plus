package asn1plus

/*
set.go contains all private functions pertaining to the
ASN.1 SET type.
*/

import (
	"reflect"
	"slices"
)

func isSet(target any, opts *Options) (set bool) {
	t := derefTypePtr(refTypeOf(target))
	o := deferImplicit(opts)
	sfx := hasSfx(t.Name(), "SET")
	if t.Kind() == reflect.Slice {
		k := t.Elem().Kind()
		if k != reflect.Uint8 && t != refTypeOf(TLV{}) {
			set = sfx || o.Tag() == TagSet || o.Set
		}
	} else if sfx {
		set = true
	}

	return
}

/*
marshalSet returns an error following an attempt to encode a SET.
Each element is encoded with its own implicit defaults.
*/
func marshalSet(v reflect.Value, pkt PDU, opts *Options) (err error) {
	v = derefValuePtr(v)
	if v.Kind() == reflect.Struct {
		var extIdx int
		if extIdx, err = findExtensibleIndex(v.Type(), opts); err != nil {
			return
		}
		if extIdx >= 0 {
			return marshalSetWithExtensions(v, pkt, opts, extIdx)
		}
		found := false
		for i := 0; i < v.NumField(); i++ {
			if field := v.Type().Field(i); field.PkgPath == "" {
				f := derefValuePtr(v.Field(i))
				if f.Kind() == reflect.Slice {
					v = f
					found = true
					break
				}
			}
		}
		if !found {
			err = compositeErrorf("marshalSet: no suitable slice field found in struct")
			return
		}
	} else if v.Kind() != reflect.Slice {
		err = compositeErrorf("marshalSet: value is not a slice or struct containing a slice")
		return
	}

	var elements [][]byte
	var typ EncodingRule = pkt.Type()
	for i := 0; i < v.Len() && err == nil; i++ {
		tmp := typ.New()
		subOpts := clearChildOpts(opts)

		subOpts.incDepth()
		if err = marshalValue(v.Index(i), tmp, subOpts); err == nil {
			elements = append(elements, tmp.Data())
		}
	}

	if err != nil {
		err = compositeErrorf("marshalSet: error marshaling slice element: ", err)
		return
	}

	if typ.canonicalOrdering() {
		slices.SortFunc(elements, func(a, b []byte) int { return bcmp(a, b) })
	}

	bufPtr := getBuf()
	concatenated := *bufPtr
	for _, e := range elements {
		concatenated = append(concatenated, e...)
	}

	tag, class := effectiveHeader(TagSet, ClassUniversal, opts)
	tlv := typ.newTLV(class, tag, len(concatenated), true, concatenated...)
	encoded := encodeTLV(tlv, nil)
	putBuf(bufPtr)

	pkt.Append(encoded...)
	return
}

func marshalSetWithExtensions(
	v reflect.Value,
	pkt PDU,
	opts *Options,
	extIdx int,
) (err error) {
	sub := pkt.Type().New()
	for i := 0; i < v.NumField() && err == nil; i++ {
		if sf := v.Type().Field(i); sf.PkgPath == "" {
			f := derefValuePtr(v.Field(i))
			var fOpts *Options
			if fOpts, err = extractOptions(sf, i, opts != nil && opts.Automatic); err == nil {
				if i == extIdx {
					raw := v.Field(i).Interface().([]TLV)
					err = marshalSequenceExtensionField(raw, sub, fOpts)
					continue
				}
				if fOpts.OmitEmpty && f.IsZero() {
					continue
				}
				if fOpts.defaultEquals(f.Interface()) {
					continue
				}
				fOpts.incDepth()
				err = marshalValue(refValueOf(f.Interface()), sub, fOpts)
			}
		}
	}

	if err == nil {
		content := sub.Data()
		tag, class := effectiveHeader(TagSet, ClassUniversal, opts)
		tlv := pkt.Type().newTLV(class, tag, len(content), true, content...)
		pkt.Append(encodeTLV(tlv, nil)...)
	}

	return
}

/*
unmarshalSet returns an error following an attempt to decode a SET
from pkt into the value v. v is expected to be either a slice (e.g.
[]Integer) or a struct whose first exported field is a slice.
*/
func unmarshalSet(v reflect.Value, pkt PDU, opts *Options) (err error) {

	if v.Kind() == reflect.Struct {
		var extIdx int
		if extIdx, err = findExtensibleIndex(v.Type(), opts); err != nil {
			return
		}
		if extIdx >= 0 {
			return unmarshalSetWithExtensions(v, pkt, opts, extIdx)
		}
		if v, err = unmarshalSequenceAsSet(v); err != nil {
			return
		}
	} else if v.Kind() != reflect.Slice {
		err = compositeErrorf("unmarshalSet: target value is not a slice or struct containing a slice")
		return
	}

	// Peel off an outer SET container if present.
	cur := pkt.Offset()
	if cur < pkt.Len() {
		raw := pkt.Data()[cur]
		// Check if the next TLV is a universal SET (class 0, tag number 17).
		if (raw&0xC0) == 0 && (raw&0x1F) == 17 {
			var outerTLV TLV
			if outerTLV, err = pkt.TLV(); err != nil {
				return err
			}
			subData := outerTLV.Value
			subPkt := pkt.Type().New(subData...)
			subPkt.SetOffset()
			pkt = subPkt
		}
	}

	elemType := v.Type().Elem()
	var elements []reflect.Value

	subOpts := clearChildOpts(opts)
	isCh := isChoice(v, opts)

	for pkt.HasMoreData() {
		var tmp reflect.Value
		if elemType.Kind() == reflect.Ptr {
			tmp = refNew(elemType.Elem())
		} else {
			tmp = refNew(elemType).Elem()
		}

		if isCh {
			tmp, err = unmarshalSetOfChoice(pkt, tmp, subOpts, elemType)
		} else {
			err = unmarshalValue(pkt, tmp, subOpts)
		}
		if err != nil {
			err = compositeErrorf("unmarshalSet: error unmarshaling SET element: ", err)
			return
		}
		elements = append(elements, tmp)
	}

	newSlice := refMkSl(v.Type(), len(elements), len(elements))
	for i, el := range elements {
		newSlice.Index(i).Set(el)
	}

	refSetValue(v, newSlice)
	return
}

func unmarshalSequenceAsSet(v reflect.Value) (reflect.Value, error) {
	var (
		found bool
		err   error
	)

	if v.NumField() == 1 {
		field := v.Type().Field(0)
		if field.PkgPath == "" {
			f := derefValuePtr(v.Field(0))
			if f.Kind() == reflect.Slice {
				v = f
				found = true
			} else {
				err = compositeErrorf("unmarshalSet: struct field ", field.Name,
					" is not a slice; got ", f.Kind().String())
			}
		}
	}

	if !found && err == nil {
		err = compositeErrorf("unmarshalSet: no suitable slice field found in struct")
	}

	return v, err
}

func setPickChoiceAlternative(
	pkt PDU,
	parentOpts *Options,
) (
	tag int,
	payload []byte,
	payloadPK PDU,
	childOpts *Options,
	err error,
) {
	typ := pkt.Type()

	// If the next TLV is a universal SET, strip it and recurse
	if tlv, pe := pkt.PeekTLV(); pe == nil &&
		tlv.Class == ClassUniversal && tlv.Tag == TagSet {
		if _, err = pkt.TLV(); err == nil {
			sub := typ.New(tlv.Value...)
			sub.SetOffset()
			tag, payload, payloadPK, childOpts, err = setPickChoiceAlternative(sub, parentOpts)
		}
		return
	}

	// Consume the context-specific wrapper TLV ([n] EXPLICIT)
	var outer TLV
	if outer, err = pkt.TLV(); err == nil {
		pkt.AddOffset(outer.Length)

		childOpts = clearChildOpts(parentOpts)
		childOpts.Choices = parentOpts.Choices

		payload = outer.Value
		tag = outer.Tag
		payloadPK = typ.New(payload...)
		payloadPK.SetOffset()
	}

	return
}

func unmarshalSetOfChoice(
	pkt PDU,
	tmp reflect.Value,
	parentOpts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {

	tag, _, payloadPK, opts, err := setPickChoiceAlternative(pkt, parentOpts)
	if err != nil {
		return tmp, err
	}
	return setDecodeChoiceSingle(tmp, tag, payloadPK, opts, elemType)
}

func setDecodeChoiceSingle(
	tmp reflect.Value,
	tag int,
	payloadPK PDU,
	opts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {
	choices, ok := GetChoices(opts.Choices)
	if !ok || choices.Len() == 0 {
		return tmp, mkerr("no CHOICE registry for SET element")
	}
	choiceIface := refTypeOf((*Choice)(nil)).Elem()
	cd, ok := choices.lookupDescriptorByInterface(choiceIface)
	if !ok {
		return tmp, mkerr("no CHOICE registry for SET element")
	}

	altT, ok := cd.tagToType[tag]
	if !ok {
		return tmp, mkerrf("no CHOICE variant for tag ", itoa(tag))
	}

	destPtr := reflect.New(altT)
	childOpts := *opts
	childOpts.tag = nil

	if err := unmarshalValue(payloadPK, destPtr.Elem(), &childOpts); err != nil {
		return tmp, mkerrf("inner decode failed: ", err.Error())
	}

	outChoice := NewChoice(destPtr.Elem().Interface())
	if elemType.Kind() == reflect.Ptr {
		tmp.Elem().Set(refValueOf(outChoice))
	} else {
		tmp.Set(refValueOf(outChoice))
	}
	return tmp, nil
}

func unmarshalSetWithExtensions(
	v reflect.Value,
	pkt PDU,
	opts *Options,
	extIdx int,
) (err error) {
	v = derefValuePtr(v)
	auto := opts != nil && opts.Automatic
	cur := pkt.Offset()
	if cur < pkt.Len() {
		raw := pkt.Data()[cur]
		if (raw&0xC0) == 0 && (raw&0x1F) == TagSet {
			var outer TLV
			if outer, err = pkt.TLV(); err != nil {
				return
			}
			sub := pkt.Type().New(outer.Value...)
			sub.SetOffset()
			pkt = sub
		}
	}

	for i := 0; i < v.NumField(); i++ {
		sf := v.Type().Field(i)
		if sf.PkgPath != "" {
			continue
		}
		f := v.Field(i)
		fOpts, err2 := extractOptions(sf, i, auto)
		if err2 != nil {
			return err2
		}

		if i == extIdx {
			var exts []TLV
			for pkt.HasMoreData() {
				var tlv TLV
				if tlv, err = pkt.TLV(); err != nil {
					return
				}
				pkt.AddOffset(tlv.Length)
				exts = append(exts, tlv)
			}
			if err = refSetValue(f, reflect.ValueOf(exts)); err != nil {
				return
			}
			continue
		}

		if err = unmarshalValue(pkt, f, fOpts); err != nil {
			return compositeErrorf(
				"unmarshalSet field ", sf.Name, ": ", err,
			)
		}
	}

	return nil
}
