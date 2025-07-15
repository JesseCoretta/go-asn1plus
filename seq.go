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

	seqTag := getSequenceTag(globalOpts)

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
			if fieldOpts.ComponentsOf {
				if !field.Anonymous {
					err = errorComponentsNotAnonymous
				} else {
					err = marshalSequenceComponentsOf(fv, sub, fieldOpts, globalOpts, auto)
				}
				continue
			}

			if fieldOpts.hasRegisteredDefault() && fieldOpts.defaultEquals(fv.Interface()) {
				// omit this field from the sequence
				continue
			}

			if err = checkSequenceFieldCriticality(field.Name, fv, fieldOpts.Optional); err == nil {
				err = applyFieldConstraints(fv.Interface(), fieldOpts.Constraints, '^')
				if err == nil {
					if isChoice(fv, fieldOpts) {
						// CHOICE field: do our explicit CHOICE handling.
						err = marshalChoiceWrapper(fv, sub, fieldOpts, fv)
					} else {
						// For all non-CHOICE fields, recurse marshalSequence
						fieldOpts.incDepth()
						err = marshalValue(fv, sub, fieldOpts)
					}
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

func marshalSequenceComponentsOf(fv reflect.Value, sub PDU, fOpts, gOpts *Options, auto bool) (err error) {
	et := fv.Type()
	for j := 0; j < et.NumField() && err == nil; j++ {
		sf := et.Field(j)
		if sf.PkgPath != "" {
			continue
		}
		var sfOpts *Options
		if sfOpts, err = extractOptions(sf, j, auto); err == nil {
			sfOpts.copyDepth(fOpts)
			sfv := fv.Field(j)
			if sfOpts.hasRegisteredDefault() && sfOpts.defaultEquals(sfv.Interface()) {
				continue
			}
			if err = checkSequenceFieldCriticality(sf.Name, sfv, sfOpts.Optional); err == nil {
				err = applyFieldConstraints(sfv.Interface(), sfOpts.Constraints, '^')
				if err == nil {
					if isChoice(sfv, sfOpts) {
						err = marshalChoiceWrapper(sfv, sub, sfOpts, sfv)
					} else {
						sfOpts.incDepth()
						err = marshalValue(sfv, sub, sfOpts)
					}
				}
			}
		}
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

		fieldOpts := implicitOptions()
		if field.Tag != "" {
			fieldOpts, err = extractOptions(field, i, auto)
		}

		fv := v.Field(i)
		if fieldOpts.ComponentsOf {
			if !field.Anonymous {
				err = errorComponentsNotAnonymous
			} else {
				err = unmarshalSequenceComponentsOf(fv, sub, fieldOpts, auto)
			}
			continue
		}

		if err == nil {
			if err = unmarshalValue(sub, fv, fieldOpts); err != nil {
				if fieldOpts.Default != nil && fieldOpts.defaultKeyword != "" {
					fv.Set(refValueOf(fieldOpts.Default))
					err = nil
				} else {
					// TODO: I still don't like this.
					err = mkerrf("unmarshalValue: failed for field ", field.Name, ": ", err.Error())
					berr := checkSequenceFieldCriticality(field.Name, fv, fieldOpts.Optional)
					if berr == nil {
						err = berr
					}
				}
			} else {
				err = applyFieldConstraints(fv.Interface(), fieldOpts.Constraints, '$')
			}
		}
	}

	return
}

func unmarshalSequenceComponentsOf(fv reflect.Value, sub PDU, fieldOpts *Options, auto bool) (err error) {
	et := fv.Type()
	for j := 0; j < et.NumField() && err == nil; j++ {
		sf := et.Field(j)
		if sf.PkgPath != "" {
			continue
		}
		sfOpts := implicitOptions()
		if sf.Tag != "" {
			sfOpts, err = extractOptions(sf, j, auto)
			if err != nil {
				continue
			}
		}
		sfOpts.copyDepth(fieldOpts)
		sfv := fv.Field(j)
		if err = unmarshalValue(sub, sfv, sfOpts); err != nil {
			if sfOpts.Default != nil && sfOpts.defaultKeyword != "" {
				sfv.Set(refValueOf(sfOpts.Default))
				err = nil
			} else {
				berr := checkSequenceFieldCriticality(sf.Name, sfv, sfOpts.Optional)
				if berr == nil {
					err = mkerrf("unmarshalValue: failed for field ", sf.Name, ": ", err.Error())
				} else {
					err = berr
				}
			}
		} else {
			err = applyFieldConstraints(sfv.Interface(), sfOpts.Constraints, '$')
		}
	}

	return
}
