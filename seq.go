package asn1plus

/*
seq.go contains all private functions pertaining to the
ASN.1 SEQUENCE composite type which, in Go, manifests
as a struct.
*/

import "reflect"

/*
marshalSequence returns an error following an
attempt to marshal sequence (struct) v into pkt.
*/
func marshalSequence(v reflect.Value, pkt PDU, opts *Options) (err error) {
	if isSet(v.Interface(), opts) {
		err = marshalSet(v, pkt, opts)
		return
	}

	seqTag := getSequenceTag(opts) // use opts.Tag OR fallback to 16
	auto := opts != nil && opts.Automatic
	sub := pkt.Type().New()

	typ := v.Type()

	for i := 0; i < v.NumField() && err == nil; i++ {
		if field := typ.Field(i); field.PkgPath == "" {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				if fOpts.ComponentsOf {
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

func marshalSequenceField(name string, v, fv reflect.Value, pkt PDU, opts *Options) (err error) {
	if opts.defaultEquals(fv.Interface()) {
		// Value matches the known default, so return early.
		return
	}

	if (opts != nil && opts.OmitEmpty) && fv.IsZero() {
		// Value is zero and omitempty was declared.
		return
	}

	// Check optional vs. missing value state
	if err = checkSequenceFieldCriticality(name, fv, opts.Optional); err == nil {
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
	if handled = isChoice(fv, opts); handled {
		// fv is a bonafide Choice interface instance
		err = marshalChoiceWrapper(fv, pkt, opts, fv)
	} else if handled = isInterfaceChoice(fv, opts); handled {
		// User is treating a non Choice interface
		// as a Choice. Artificially wrap fv.
		ch := refValueOf(NewChoice(fv.Interface(), opts.Tag()))
		err = marshalChoiceWrapper(v, pkt, opts, ch)
	}
	return
}

func getSequenceTag(o *Options) (seqTag int) {
	seqTag = TagSequence // 16
	if o != nil {
		switch {
		case o.HasTag(): // caller supplied a tag
			seqTag = o.Tag()
		case o.Class() != ClassUniversal: // class changed ⇒ default tag 0
			seqTag = 0
		}
	}
	return
}

func marshalSequenceOfSlice(v reflect.Value, pkt PDU, _ *Options) (err error) {
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

func checkSequenceFieldCriticality(name string, fv reflect.Value, optional bool) (err error) {
	if !optional {
		if fv.Kind() == reflect.Invalid || fv.Interface() == nil {
			err = compositeErrorf(errorSeqEmptyNonOptField, ": ", name)
		}
	}

	return
}

func marshalSequenceWrap(sub, pkt PDU, opts *Options, seqTag int) (err error) {
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

	// Whether automatic tagging is enabled.
	var auto bool = opts != nil && opts.Automatic

	typ := v.Type()
	for i := 0; i < v.NumField() && err == nil; i++ {
		if field := typ.Field(i); field.PkgPath == "" {
			var fOpts *Options
			if fOpts, err = extractOptions(field, i, auto); err == nil {
				if fOpts.ComponentsOf {
					err = unmarshalSequenceComponentsOf(field, v.Field(i), sub, fOpts, auto)
				} else {
					err = unmarshalSequenceField(field.Name, v.Field(i), sub, fOpts)
				}
			}
		}
	}

	return
}

func unmarshalSequenceField(
	name string,
	fv reflect.Value,
	sub PDU,
	opts *Options,
) (err error) {
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
				if berr := checkSequenceFieldCriticality(name, fv, opts.Optional); berr == nil {
					err = berr
				}
			}
		}

		if err == nil {
			err = applyFieldConstraints(
				fv.Interface(), opts.Constraints, '$',
			)
		}
	}

	return
}

func unmarshalSequenceFieldOptionalEmpty(
	sub PDU,
	opts *Options,
) (handled bool, err error) {
	if opts == nil || !opts.OmitEmpty {
		return false, nil
	}

	if sub.Len()-sub.Offset() == 0 {
		return true, nil
	}

	tlv, peekErr := sub.PeekTLV()
	if peekErr != nil {
		// peek-failure means “no TLV here” → skip
		return true, nil
	}

	expClass, expTag, err := getTLVResolveOverride(
		/* original class */ opts.Class(),
		/* original tag   */ opts.Tag(),
		/* compound?      */ false,
		opts,
	)
	if err != nil {
		return false, err
	}

	if tlv.Class != expClass || tlv.Tag != expTag {
		return true, nil
	}
	return false, nil
}

func unmarshalSequenceComponentsOf(
	field reflect.StructField,
	v reflect.Value,
	sub PDU,
	opts *Options,
	auto bool,
) (err error) {
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
