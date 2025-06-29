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
func marshalSequence(v reflect.Value, pkt Packet, globalOpts *Options, depth int) (err error) {
	if isSet(v.Interface(), globalOpts) {
		err = marshalSet(v, pkt, globalOpts, depth)
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

			fv := v.Field(i)

			if err = checkSequenceFieldCriticality(field.Name, fv, fieldOpts.Optional); err == nil {
				if ch, ok := fv.Interface().(Choice); ok {
					// CHOICE field: do our explicit CHOICE handling.
					err = marshalSequenceChoiceField(fieldOpts, ch, sub, depth)
				} else {
					// For all non-CHOICE fields, recurse marshalSequence
					err = marshalValue(fv, sub, fieldOpts, depth+1)
				}
			}
		}
	}

	if err == nil {
		// wrap the entire sequence from the sub-packet.
		err = marshalSequenceWrap(sub, pkt, globalOpts, depth, seqTag)
	}

	return
}

func checkSequenceFieldCriticality(name string, fv reflect.Value, optional bool) (err error) {
	if !optional {
		if fv.Kind() == reflect.Invalid || fv.Interface() == nil {
			err = mkerrf("marshalSequence: missing required value for field ", name)
		}
	}

	return
}

func marshalSequenceWrap(sub, pkt Packet, opts *Options, depth, seqTag int) (err error) {
	var tlv TLV
	sub.SetOffset(0)
	if depth == 1 && opts != nil {
		content := sub.Data()
		tlv = pkt.Type().newTLV(opts.Class(), seqTag, len(content), true, content...)
		encoded := encodeTLV(tlv, opts)
		pkt.Append(encoded...)
	} else {
		content := sub.Data()
		tlv := pkt.Type().newTLV(ClassUniversal, TagSequence, len(content), true, content...)
		pkt.Append(encodeTLV(tlv, nil)...)
	}

	return
}

func marshalSequenceChoiceField(opts *Options, ch Choice, sub Packet, depth int) (err error) {
	if ch.Tag != nil {
		opts.choiceTag = ch.Tag
		opts.SetClass(ClassContextSpecific)
	}

	if isPrimitive(ch.Value) {
		err = marshalSequenceChoiceFieldPrimitive(opts, ch, sub)
	} else {
		err = marshalSequenceChoiceFieldNonPrimitive(opts, ch, sub, depth)
	}

	return
}

func marshalSequenceChoiceFieldNonPrimitive(opts *Options, ch Choice, sub Packet, depth int) (err error) {
	tmp := sub.Type().New()
	defer tmp.Free()
	if err = marshalValue(refValueOf(ch.Value), tmp, opts, depth+1); err == nil {
		innerEnc := tmp.Data()

		// Now build an explicit wrapper using opts.
		// The identifier for an explicit context-specific tag is computed as:
		//    (opts.Class << 6) | 0x20 | byte((*opts.choiceTag))
		// use context tag [N] (opts.choiceTag), and **NOT** the type tag
		id := marshalSequenceSetChoiceTag(opts.Class(), opts.choiceTag)
		sub.Append(id)
		bufPtr := getBuf()
		encodeLengthInto(sub.Type(), bufPtr, len(innerEnc))
		sub.Append(*bufPtr...)
		putBuf(bufPtr)
		sub.Append(innerEnc...)
	}

	return
}

func marshalSequenceChoiceFieldPrimitive(opts *Options, ch Choice, sub Packet) (err error) {
	// COVERAGE: unreachable
	//if c, ok := toPtr(refValueOf(ch.Value)).Interface().(codecRW); ok {
	//_, err = c.write(sub, opts)
	if bx, ok := createCodecForPrimitive(ch.Value); ok {
		_, err = bx.write(sub, opts)
	} else {
		err = mkerr("marshalSequence: no codec for CHOICE primitive")
	}

	if err == nil && ch.Explicit {
		inner := sub.Data()[sub.Offset():]
		// rebuild the sub-packet to insert the wrapper
		wrapped := sub.Type().New()
		wrapped.Append(marshalSequenceSetChoiceTag(ClassContextSpecific, ch.Tag))
		bufPtr := getBuf()
		encodeLengthInto(sub.Type(), bufPtr, len(inner))
		wrapped.Append(*bufPtr...)
		putBuf(bufPtr)
		wrapped.Append(inner...)

		// replace the old bytes in sub
		nsub := sub.Type().New(sub.Data()[:sub.Offset()]...)
		nsub.Append(wrapped.Data()...)
		sub = nsub
	}

	return
}

func marshalSequenceSetChoiceTag(class int, tag *int) (id byte) {
	if tag == nil {
		tag = new(int)
	}
	id = byte(class<<6) | 0x20 | byte(*tag)
	return
}

/*
unmarshalSequence returns an error following an attempt to write pkt into sequence (struct) v.
*/
func unmarshalSequence(v reflect.Value, pkt Packet, options *Options) (err error) {

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
	var auto bool
	var choicesMap map[string]Choices

	if options != nil {
		auto = options.Automatic
		choicesMap = options.ChoicesMap
	}

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
			opts.ChoicesMap = choicesMap

			fv := v.Field(i)
			switch fv.Interface().(type) {
			case Choice, *Choice:
				var alt Choice
				if alt, err = selectFieldChoice(field.Name, v.Interface(), sub, opts); err == nil {
					fv.Set(refValueOf(Choice{Value: alt.Value}))
				}
			default:
				if err = unmarshalValue(sub, fv, opts); err != nil {
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
