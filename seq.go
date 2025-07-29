package asn1plus

/*
seq.go contains all private functions pertaining to the
ASN.1 SEQUENCE composite type which, in Go, manifests
as a struct.
*/

import "reflect"

/*
RawContent implements a []byte slice in the same context
as the [encoding/asn1.RawContent] type.
*/
type RawContent []byte

/*
marshalSequence returns an error following an
attempt to marshal sequence (struct) v into pkt.
*/
func marshalSequence(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() { debugExit(newLItem(err)) }()

	typ := v.Type()
	fields := structFields(typ)
	rawIdx := findRawContentIndex(typ, fields)

	if isSet(v.Interface(), opts) {
		err = marshalSet(v, pkt, opts)
		return
	}

	seqTag := getSequenceTag(opts) // use opts.Tag OR fallback to 16

	var extIdx int
	if extIdx, err = findExtensibleIndex(fields, opts); err != nil {
		return
	}

	sub := pkt.Type().New()
	auto := optsIsAutoTag(opts)

	for i := 0; i < len(fields) && err == nil; i++ {
		if field := fields[i]; field.PkgPath == "" && rawIdx != i {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				if i == extIdx {
					err = marshalSequenceExtensionField(v.Field(i), sub, fOpts)
				} else if fOpts.ComponentsOf {
					err = marshalSequenceComponentsOf(field, v.Field(i), sub, fOpts, auto)
				} else {
					err = marshalSequenceField(field.Name, v, v.Field(i), sub, fOpts)
				}
			}
		}
	}

	if err == nil {
		err = marshalSequenceWrap(sub, pkt, opts, seqTag)
	}

	return
}

/*
structFields returns slices of [reflect.StructField].
*/
func structFields(t reflect.Type) (fields []reflect.StructField) {
	t = derefTypePtr(t)
	if t.Kind() == reflect.Struct {
		num := t.NumField()
		fields = make([]reflect.StructField, 0, num)

		for i := 0; i < num; i++ {
			fields = append(fields, t.Field(i))
		}
	}
	return fields
}

func marshalSequenceExtensionField(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() { debugExit(newLItem(err)) }()

	tlvs, ok := v.Interface().([]TLV)
	if !ok {
		err = generalErrorf("Assertion error: expected []TLV, got ", v.Type())
	} else {
		for i := 0; i < len(tlvs) && err == nil; i++ {
			err = writeTLV(pkt, tlvs[i], opts)
		}
	}
	return
}

func marshalSequenceField(name string, v, fv reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(newLItem(name, "field"), v, fv, pkt, opts)
	defer func() { debugExit(newLItem(err)) }()

	if opts.defaultEquals(fv.Interface()) {
		// Value matches the known default, so return early.
		return
	}

	if optsIsOmit(opts) && fv.IsZero() {
		// Value is zero and omitempty was declared.
		return
	}

	// Check optional vs. missing value state
	if err = checkSequenceFieldCriticality(name, fv, opts); err == nil {
		// Apply any constraints (if we're supposed to)
		if err = applyFieldConstraints(fv.Interface(), opts.Constraints, '^'); err == nil {
			var handled bool
			// If field is some kind of Choice, handle it.
			handled, err = marshalSequenceFieldChoice(v, fv, pkt, opts)
			if !handled {
				// ... otherwise marshal value as usual.
				opts.incDepth()
				err = marshalValue(fv, pkt, opts)
			}
		}
	}

	return
}

func marshalSequenceComponentsOf(
	field reflect.StructField,
	v reflect.Value,
	sub PDU,
	opts *Options,
	auto bool,
) (err error) {
	debugEnter(newLItem(field.Name, "field"),
		newLItem(auto, "auto tag"), v, sub, opts)
	defer func() { debugExit(newLItem(err)) }()

	if !field.Anonymous {
		err = errorComponentsNotAnonymous
		return
	}

	t := v.Type()
	for i := 0; i < t.NumField() && err == nil; i++ {
		if field = t.Field(i); field.PkgPath == "" {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				fOpts.copyDepth(opts)
				err = marshalSequenceField(field.Name, v, v.Field(i), sub, fOpts)
			}
		}
	}

	return
}

func marshalSequenceFieldChoice(v, fv reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {
	debugEnter(v, fv, pkt, opts)
	defer func() { debugExit(newLItem(handled, "handled"), newLItem(err)) }()

	if handled = isChoice(fv, opts); handled {
		// fv is a bonafide Choice interface instance
		err = marshalChoiceWrapper(v, pkt, opts, fv)
	} else if handled = isInterfaceChoice(fv, opts); handled {
		// User is treating a non Choice interface
		// as a Choice. Artificially wrap fv.
		ch := refValueOf(NewChoice(fv.Interface(), opts.Tag()))
		err = marshalChoiceWrapper(v, pkt, opts, ch)
	}
	return
}

func getSequenceTag(o *Options) (seqTag int) {
	debugEnter(o)

	seqTag = TagSequence // 16
	if o != nil {
		switch {
		case o.HasTag(): // caller supplied a tag
			seqTag = o.Tag()
		case o.Class() != ClassUniversal: // class changed: default tag 0
			seqTag = 0
		}
	}

	debugExit(newLItem(seqTag, "seq tag"))
	return
}

func marshalSequenceOfSlice(v reflect.Value, pkt PDU, _ *Options) (err error) {
	debugEnter(v, pkt)
	defer func() { debugExit(newLItem(err)) }()

	typ := pkt.Type()
	sub := typ.New()
	for i := 0; i < v.Len() && err == nil; i++ {
		err = marshalValue(v.Index(i), sub, implicitOptions())
	}

	if err == nil {
		id := emitHeader(ClassUniversal, TagSequence, true)
		debugPrim(newLItem(id, "header"))
		pkt.Append(id)
		content := sub.Data()

		bufPtr := getBuf()
		encodeLengthInto(typ, bufPtr, len(content))
		pkt.Append(*bufPtr...)
		putBuf(bufPtr)

		pkt.Append(content...)
	}

	return
}

func checkSequenceFieldCriticality(name string, fv reflect.Value, opts *Options) (err error) {
	debugEnter(newLItem(name, "field"), fv, opts)
	defer func() { debugExit(newLItem(err)) }()
	k := fv.Kind()

	if k == reflect.Ptr {
		if opts.Absent && !fv.IsNil() {
			err = errorAbsentNotNilPtr
			return
		}
	} else if opts.Absent {
		err = errorAbsentNotNilPtr
		return
	}

	if !opts.Optional {
		if k == reflect.Invalid || fv.Interface() == nil {
			err = compositeErrorf(errorSeqEmptyNonOptField, ": ", name)
		}
	}

	return
}

func marshalSequenceWrap(sub, pkt PDU, opts *Options, seqTag int) (err error) {
	debugEnter(sub, pkt, opts, newLItem(seqTag, "seq tag"))
	defer func() { debugExit(newLItem(err)) }()

	sub.SetOffset(0)
	content := sub.Data()

	class := ClassUniversal
	tag := TagSequence

	if opts != nil {
		if opts.depth == 1 {
			class = opts.Class()
			tag = seqTag
		} else if opts.HasTag() {
			class = opts.Class()
			tag = opts.Tag()
		}
	}

	tlv := pkt.Type().newTLV(class, tag, len(content), true, content...)
	pkt.Append(encodeTLV(tlv, opts)...)

	return
}

/*
unmarshalSequence returns an error following an attempt to write pkt into sequence (struct) v.
*/
func unmarshalSequence(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, pkt, opts)
	defer func() { debugExit(newLItem(err)) }()

	var tlv TLV
	if tlv, err = pkt.TLV(); err != nil {
		err = compositeErrorf("unmarshalValue: reading SEQUENCE TL header failed: ", err)
		return
	}

	start := pkt.Offset()
	end := start + tlv.Length
	if end > pkt.Len() {
		err = compositeErrorf("unmarshalValue: insufficient data for SEQUENCE content")
		return
	}

	seqContent := pkt.Data()[start:end]
	pkt.SetOffset(end)
	sub := pkt.Type().New(seqContent...)
	sub.SetOffset(0)

	typ := v.Type()
	fields := structFields(typ)

	if rawIdx := findRawContentIndex(typ, fields); rawIdx == 0 {
		if err = refSetValue(v.Field(0), refValueOf(tlv.Value)); err != nil {
			return
		}
	}

	var extIdx int
	if extIdx, err = findExtensibleIndex(fields, opts); err != nil {
		return
	}

	auto := optsIsAutoTag(opts)
	for i := 0; i < len(fields) && err == nil; i++ {
		if field := fields[i]; field.PkgPath == "" {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				if i == extIdx {
					err = unmarshalSequenceExtensionField(v.Field(i), sub, fOpts)
				} else if field.Type == rawContentType && i != 0 {
					err = errorExtensionNotFieldZero
				} else if fOpts.ComponentsOf {
					err = unmarshalSequenceComponentsOf(field, v.Field(i), sub, fOpts, auto)
				} else {
					err = unmarshalSequenceField(field.Name, v.Field(i), sub, fOpts)
				}
			}
		}
	}

	return
}

func unmarshalSequenceExtensionField(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() { debugExit(newLItem(err)) }()

	var exts []TLV
	for pkt.HasMoreData() && err == nil {
		var tlv TLV
		if tlv, err = pkt.TLV(); err == nil {
			pkt.AddOffset(tlv.Length)
			exts = append(exts, tlv)
		}
	}
	debugComposite(newLItem(len(exts), "TLVs unmarshaled"))

	if err == nil {
		err = refSetValue(v, refValueOf(exts))
	}
	return
}

func unmarshalSequenceField(
	name string,
	fv reflect.Value,
	sub PDU,
	opts *Options,
) (err error) {
	debugEnter(newLItem(name, "field"), fv, opts, sub)
	defer func() { debugExit(newLItem(err)) }()

	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			err = refSetValue(fv, refNew(fv.Type().Elem()))
		}
		if err == nil {
			err = unmarshalSequenceField(name, fv.Elem(), sub, opts)
		}
		return
	}

	var handled bool
	if handled, err = unmarshalSequenceFieldOptionalEmpty(sub, opts); err != nil {
		return err
	} else if handled {
		return nil
	}

	if err = unmarshalUnwrapInterfaceChoice(sub, fv, opts); err == nil {
		if err = unmarshalValue(sub, fv, opts); err != nil {
			// Error *might* be recoverable.
			def := opts.Default
			if def == nil {
				def, _ = lookupDefaultValue(opts.defaultKeyword)
			}
			if def != nil {
				err = refSetValue(fv, refValueOf(def))
			} else {
				err = compositeErrorf(
					"unmarshalValue: failed for field ", name, ": ", err,
				)
				if berr := checkSequenceFieldCriticality(name, fv, opts); berr == nil {
					err = berr
				}
			}
		}

		if err == nil {
			err = applyFieldConstraints(
				fv.Interface(), opts.Constraints, '$')
		}
	}

	return
}

func unmarshalSequenceFieldOptionalEmpty(
	sub PDU,
	opts *Options,
) (handled bool, err error) {

	debugEnter(opts, sub)
	defer func() { debugExit(err) }()

	abs := optsIsAbsent(opts)
	mask := EventComposite | EventTrace

	// skip non-OPTIONAL/non-ABSENT
	if !optsIsOptional(opts) && !(abs || optsHasDefault(opts)) {
		debugEvent(mask,
			newLItem(handled, "handled"),
			newLItem("skip non-ABSENT/non-OPTIONAL"))
		return
	}

	// always skip ABSENT
	if abs {
		handled = true
		debugEvent(mask,
			newLItem(handled, "handled"),
			newLItem("skip ABSENT"))
		return
	}

	// skip empty OPTIONAL
	if !sub.HasMoreData() {
		handled = true
		debugEvent(mask,
			newLItem(handled, "handled"),
			newLItem("skip OPTIONAL (no more data)"))
		return
	}

	var tlv TLV
	// OPTIONAL: peek to see if this field is actually in the data
	if tlv, err = sub.PeekTLV(); err != nil {
		handled = true
		debugEvent(mask,
			newLItem(handled, "handled"),
			newLItem("skip OPTIONAL (peek error)"))
		return
	}

	// Match options Class/Tag to TLV Class/Tag when
	// any data remains.
	if tlv.matchClassAndTag(opts.Class(), opts.Tag()) {
		debugEvent(mask,
			newLItem(handled, "handled"),
			newLItem("parse OPTIONAL: class/tag matched"))
		return
	}

	handled = true
	debugEvent(mask,
		newLItem(handled, "handled"),
		newLItem("skip OPTIONAL (next tag is",
			tlv.Class, "/", tlv.Tag, ")"))

	return
}

func unmarshalSequenceComponentsOf(
	field reflect.StructField,
	v reflect.Value,
	sub PDU,
	opts *Options,
	auto bool,
) (err error) {
	debugEnter(field, v, opts, newLItem(auto, "auto tag"), sub)
	defer func() { newLItem(err) }()

	if !field.Anonymous {
		err = errorComponentsNotAnonymous
		return
	}

	t := v.Type()
	for i := 0; i < t.NumField() && err == nil; i++ {
		if field = t.Field(i); field.PkgPath == "" {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				fOpts.copyDepth(opts)
				err = unmarshalSequenceField(field.Name, v.Field(i), sub, fOpts)
			}
		}
	}

	return
}

func findExtensibleIndex(fields []reflect.StructField, opts *Options) (idx int, err error) {
	debugEnter(opts)
	defer func() { debugExit(newLItem(err)) }()

	idx = -1
	auto := optsIsAutoTag(opts)
	for i := 0; i < len(fields); i++ {
		if sf := fields[i]; sf.PkgPath == "" {
			var opts *Options
			if opts, err = extractOptions(sf, i, auto); err == nil && opts.Extension {
				if sf.Type.Kind() != reflect.Slice || sf.Type.Elem() != tLVType {
					err = compositeErrorf("extension field ", i, " must be []TLV")
				} else {
					idx = i
				}
				break
			}
		}
	}

	debugEvent(EventComposite|EventTrace,
		newLItem(idx, "extensible index"))

	return
}

func findRawContentIndex(typ reflect.Type, fields []reflect.StructField) (idx int) {
	debugEnter(typ)

	idx = -1
	if typ.Kind() == reflect.Struct && len(fields) > 0 {
		if sf := fields[0]; sf.PkgPath == "" && sf.Type == rawContentType {
			idx = 0
		}
	}

	debugEvent(EventComposite|EventTrace,
		newLItem(idx, "raw content index"))

	return
}
