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
func marshalSequence(v reflect.Value, pkt PDU, globalOpts *Options) (err error) {
	if isSet(v.Interface(), globalOpts) {
		err = marshalSet(v, pkt, globalOpts)
		return
	}

	seqTag := TagSequence // 16
	if globalOpts != nil {
		switch {
		case globalOpts.HasTag(): // caller supplied a tag
			seqTag = globalOpts.Tag()
		case globalOpts.Class() != ClassUniversal: // class changed ⇒ default tag 0
			seqTag = 0
		}
	}

	// Whether automatic tagging is enabled.
	auto := globalOpts != nil && globalOpts.Automatic

	// Create a temporary sub-packet for encoding this sequence’s fields.
	sub := pkt.Type().New()

	typ := v.Type()

	for i := 0; i < v.NumField() && err == nil; i++ {
		field := typ.Field(i)
		if field.PkgPath == "" {

			// Begin with the implicit options for this field.
			var fieldOpts *Options
			if fieldOpts, err = extractOptions(field, i, auto); err != nil {
				return
			}
			fieldOpts.copyDepth(globalOpts)

			fv := v.Field(i)

			if fieldOpts.hasRegisteredDefault() && fieldOpts.defaultEquals(fv.Interface()) {
				// omit this field from the sequence
				continue
			}

			if err = checkSequenceFieldCriticality(field.Name, fv, fieldOpts.Optional); err == nil {
				if isChoice(fv, fieldOpts) {
					err = marshalChoiceWrapper(fv, sub, fieldOpts, fv)
					// CHOICE field: do our explicit CHOICE handling.
					//err = marshalSequenceChoiceField(fieldOpts, ch, sub)
				} else {
					// For all non-CHOICE fields, recurse marshalSequence
					fieldOpts.incDepth()
					err = marshalValue(fv, sub, fieldOpts)
				}
			}
		}
	}

	if err == nil {
		// wrap the entire sequence from the sub-packet.
		err = marshalSequenceWrap(sub, pkt, globalOpts, seqTag)
	}

	return
}

func marshalSequenceOfSlice(v reflect.Value, pkt PDU, _ *Options) (err error) {
	sub := pkt.Type().New()
	for i := 0; i < v.Len() && err == nil; i++ {
		err = marshalValue(v.Index(i), sub, implicitOptions())
	}

	if err == nil {
		// Construct the identifier byte: class + constructed bit + tag number
		id := byte(ClassUniversal<<6) | 0x20 | byte(TagSequence)
		pkt.Append(id)
		content := sub.Data()

		// Encode the length
		bufPtr := getBuf()
		encodeLengthInto(pkt.Type(), bufPtr, len(content))
		pkt.Append(*bufPtr...)
		putBuf(bufPtr)

		pkt.Append(content...)
	}

	return
}

func checkSequenceFieldCriticality(name string, fv reflect.Value, optional bool) (err error) {
	if !optional {
		if fv.Kind() == reflect.Invalid || fv.Interface() == nil {
			err = mkerrf(errorSeqEmptyNonOptField.Error(), ": ", name)
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
func unmarshalSequence(v reflect.Value, pkt PDU, options *Options) (err error) {

	var tlv TLV
	if tlv, err = pkt.TLV(); err != nil {
		err = mkerrf("unmarshalValue: reading SEQUENCE TL header failed: ", err.Error())
		return
	}

	start := pkt.Offset()
	end := start + tlv.Length
	if end > pkt.Len() {
		err = mkerr("unmarshalValue: insufficient data for SEQUENCE content")
		return
	}

	seqContent := pkt.Data()[start:end]
	pkt.SetOffset(end)
	sub := pkt.Type().New(seqContent...)
	sub.SetOffset(0)

	// Whether automatic tagging is enabled.
	var auto bool = options != nil && options.Automatic

	typ := v.Type()
	for i := 0; i < v.NumField() && err == nil; i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}

		opts := implicitOptions()
		if field.Tag != "" {
			opts, err = extractOptions(field, i, auto)
		}

		if err == nil {
			fv := v.Field(i)
			if err = unmarshalValue(sub, fv, opts); err != nil {
				if opts.Default != nil && opts.defaultKeyword != "" {
					fv.Set(refValueOf(opts.Default))
					err = nil
				} else {
					// TODO: I still don't like this.
					err = mkerrf("unmarshalValue: failed for field ", field.Name, ": ", err.Error())
					if berr := checkSequenceFieldCriticality(field.Name, fv, opts.Optional); berr == nil {
						err = berr
					}
				}
			}
		}
	}

	return
}
