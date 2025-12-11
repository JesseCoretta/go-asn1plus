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

	sliceCase := t.Kind() == reflect.Slice &&
		t != tLVType &&
		t.Elem().Kind() != reflect.Uint8

	nameHasSet := hasSfx(t.Name(), "SET")

	if sliceCase {
		set = o.Set
	} else {
		set = nameHasSet
	}

	return
}

/*
marshalSet returns an error following an attempt to encode a SET.
Each element is encoded with its own implicit defaults.
*/
func marshalSet(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, pkt, opts)
	defer func() { debugExit(newLItem(err)) }()

	v = derefValuePtr(v)
	k := v.Kind()
	if k == reflect.Struct {
		fields := structFields(v.Type())
		var extIdx int
		if extIdx, err = findExtensibleIndex(fields, opts); err != nil {
			return
		} else if extIdx >= 0 {
			err = marshalSetWithExtensions(v, fields, pkt, opts, extIdx)
			return
		}

		found := false
		for i := 0; i < len(fields); i++ {
			if field := fields[i]; field.PkgPath == "" {
				val := v.Field(i)
				if f := derefValuePtr(val); f.Kind() == reflect.Slice {
					v = f
					found = true
					break
				}
			}
		}
		if !found {
			err = compositeErrorf("marshalSet: no SET field found in struct")
			return
		}
	} else if k != reflect.Slice {
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
		debugComposite(
			newLItem(typ, "use canonical ordering"))
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
	fields []reflect.StructField,
	pkt PDU,
	opts *Options,
	extIdx int,
) (err error) {
	debugEnter(v, opts, newLItem(extIdx, "set extension"), pkt)
	defer func() { debugExit(newLItem(err)) }()

	typ := pkt.Type()
	sub := typ.New()

	for i := 0; i < len(fields) && err == nil; i++ {
		if sf := fields[i]; sf.PkgPath == "" {
			f := derefValuePtr(v.Field(i))
			var fOpts *Options
			if fOpts, err = extractOptions(sf, i, optsIsAutoTag(opts)); err == nil {
				if i == extIdx {
					err = marshalSequenceExtensionField(v.Field(i), sub, fOpts)
					continue
				} else if fOpts.OmitEmpty && f.IsZero() {
					continue
				} else if fOpts.defaultEquals(f.Interface()) {
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
		tlv := typ.newTLV(class, tag, len(content), true, content...)
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
	debugEnter(v, pkt, opts)
	defer func() { debugExit(newLItem(err)) }()

	k := v.Kind()
	if k == reflect.Struct {
		fields := structFields(v.Type())
		var extIdx int
		if extIdx, err = findExtensibleIndex(fields, opts); err != nil {
			return
		} else if extIdx >= 0 {
			return unmarshalSetWithExtensions(v, fields, pkt, opts, extIdx)
		} else if v, err = unmarshalSequenceAsSet(v, fields); err != nil {
			return
		}
	} else if k != reflect.Slice {
		err = compositeErrorf("unmarshalSet: target value is not a slice or struct containing a slice")
		return
	}

	// Peel off an outer SET container if present.
	if cur := pkt.Offset(); cur < pkt.Len() {
		raw := pkt.Data()[cur]
		// Check if the next TLV is a universal SET (class 0, tag number 17).
		if (raw&0xC0) == 0 && (raw&longByte) == TagSet {
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

	err = refSetValue(v, newSlice)
	return
}

func unmarshalSequenceAsSet(v reflect.Value, fields []reflect.StructField) (reflect.Value, error) {
	debugEnter(v)

	var (
		found bool
		err   error
	)

	if len(fields) == 1 {
		if field := fields[0]; field.PkgPath == "" {
			f := derefValuePtr(v.Field(0))
			k := f.Kind()
			if k == reflect.Slice {
				v = f
				found = true
			} else {
				err = compositeErrorf("unmarshalSet: struct field ", field.Name,
					" is not a slice; got ", k.String())
			}
		}
	}

	if !found && err == nil {
		err = compositeErrorf("unmarshalSet: no suitable slice field found in struct")
	}

	debugExit(v, newLItem(err))

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
	debugEnter(parentOpts, pkt)

	typ := pkt.Type()

	// If the next TLV is a universal SET, strip it and recurse
	if tlv, pe := pkt.PeekTLV(); pe == nil &&
		tlv.matchClassAndTag(ClassUniversal, TagSet) {
		if _, err = pkt.TLV(); err == nil {
			sub := typ.New(tlv.Value...)
			sub.SetOffset()
			tag, payload, payloadPK, childOpts, err =
				setPickChoiceAlternative(sub, parentOpts)
		}
	} else {
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
	}

	debugExit(
		newLItem(tag, "tag"),
		newLItem(payload, "payload"),
		newLItem(payloadPK, "PDU"),
		childOpts,
		newLItem(err))

	return
}

func unmarshalSetOfChoice(
	pkt PDU,
	tmp reflect.Value,
	pOpts *Options,
	elemType reflect.Type,
) (v reflect.Value, err error) {

	debugEnter(tmp, pOpts, elemType, pkt)

	var (
		tag       int
		payloadPK PDU
		opts      *Options
	)

	if tag, _, payloadPK, opts, err = setPickChoiceAlternative(pkt, pOpts); err != nil {
		v = tmp
	} else {
		v, err = setDecodeChoiceSingle(tmp, tag, payloadPK, opts, elemType)
	}

	debugExit(v, newLItem(err))

	return
}

func setDecodeChoiceSingle(
	tmp reflect.Value,
	tag int,
	payloadPK PDU,
	opts *Options,
	elemType reflect.Type,
) (v reflect.Value, err error) {
	debugEnter(newLItem(tag, "tag"), tmp, opts, elemType, payloadPK)

	var cd *choiceDescriptor

	choices, ok := GetChoices(opts.Choices)
	if !ok || choices.Len() == 0 {
		v = tmp
		err = choiceErrorf("no CHOICE registry for SET element")
	} else {
		choiceIface := refTypeOf((*Choice)(nil)).Elem()
		var ok bool
		if cd, ok = choices.lookupDescriptorByInterface(choiceIface); !ok {
			v = tmp
			err = choiceErrorf("no CHOICE registry for SET element")
		}
	}

	if err == nil {
		altT, ok := cd.tagToType[tag]
		if !ok {
			v = tmp
			err = choiceErrorf("no CHOICE variant for tag ", tag)
		} else {
			destPtr := reflect.New(altT)
			childOpts := *opts
			childOpts.tag = nil

			if err = unmarshalValue(payloadPK, destPtr.Elem(), &childOpts); err != nil {
				err = choiceErrorf("inner decode failed: ", err.Error())
				v = tmp
			} else {
				outChoice := NewChoice(destPtr.Elem().Interface())
				if elemType.Kind() == reflect.Ptr {
					v = tmp.Elem()
					err = refSetValue(tmp.Elem(), refValueOf(outChoice))
				} else {
					v = tmp
					err = refSetValue(tmp, refValueOf(outChoice))
				}
			}
		}
	}

	debugExit(v, newLItem(err))

	return
}

func unmarshalSetWithExtensions(
	v reflect.Value,
	fields []reflect.StructField,
	pkt PDU,
	opts *Options,
	extIdx int,
) (err error) {
	debugEnter(opts, newLItem(extIdx, "extension index"), pkt)
	defer func() { newLItem(err) }()

	v = derefValuePtr(v)
	auto := optsIsAutoTag(opts)
	cur := pkt.Offset()
	if cur < pkt.Len() {
		raw := pkt.Data()[cur]
		if (raw&0xC0) == 0 && (raw&longByte) == TagSet {
			var outer TLV
			if outer, err = pkt.TLV(); err != nil {
				return
			}
			sub := pkt.Type().New(outer.Value...)
			sub.SetOffset()
			pkt = sub
		}
	}

	for i := 0; i < len(fields); i++ {
		sf := fields[i]
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
			if err = refSetValue(f, refValueOf(exts)); err != nil {
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
