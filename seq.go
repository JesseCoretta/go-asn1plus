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

	// Create a temporary sub-packet for encoding this sequence’s fields.
	sub := pkt.Type().New()
	defer sub.Free()
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		// Skip unexported fields.
		if field.PkgPath != "" {
			continue
		}

		// Begin with the implicit options for this field.
		var fieldOpts Options
		if fieldOpts, err = extractOptions(field); err != nil {
			return
		}

		fv := v.Field(i)

		// If the field is of type Choice, do our explicit CHOICE handling.
		if ch, ok := fv.Interface().(Choice); ok {
			if err = marshalSequenceChoiceField(fieldOpts, ch, pkt, sub, depth); err != nil {
				err = mkerr("marshalValue failed for CHOICE field " + field.Name + ": " + err.Error())
				return
			}
		} else {
			// For all non-CHOICE fields, encode using fieldOpts.
			if err = marshalValue(fv, sub, &fieldOpts, depth+1); err != nil {
				if !fieldOpts.Optional {
					err = mkerr("marshalValue failed for field " + field.Name + ": " + err.Error())
					return
				}
			}
		}
	}

	// wrap the entire sequence from the sub-packet.
	var tlv TLV
	sub.SetOffset(0)
	if depth == 1 && globalOpts != nil {
		// At the outermost level (depth==1), if global options were provided, use them.
		content := sub.Data()
		tlv = pkt.Type().newTLV(globalOpts.Class(), seqTag, len(content), true, content...)
		encoded := encodeTLV(tlv, *globalOpts)
		pkt.Append(encoded...)
	} else if tlv, err = sub.TLV(); err == nil {
		// Inner sequences use the universal SEQUENCE tag (0x30).
		pkt.Append(0x30)
		enc := encodeTLV(tlv)
		pkt.Append(encodeLength(sub.Type(), len(enc))...)
		pkt.Append(enc...)
	}

	return
}

func marshalSequenceChoiceField(opts Options, ch Choice, pkt, sub Packet, depth int) (err error) {
	// Restore your original CHOICE code:
	if ch.Tag != nil {
		opts.choiceTag = ch.Tag
		opts.SetClass(ClassContextSpecific)
	}

	if isPrimitive(ch.Value) {
		// For a primitive alternative, simply let it write itself.
		// (Note: using toPtr as in your original code.)
		_, err = toPtr(reflect.ValueOf(ch.Value)).Interface().(Primitive).write(sub, opts)
	} else {
		// For a compound CHOICE, encode recursively.
		tmp := pkt.Type().New()
		defer tmp.Free()
		if err = marshalValue(reflect.ValueOf(ch.Value), tmp, &opts, depth+1); err == nil {
			innerEnc := tmp.Data()

			// Now build an explicit wrapper using opts.
			// The identifier for an explicit context-specific tag is computed as:
			//    (opts.Class << 6) | 0x20 | byte((*opts.choiceTag))
			// use context tag [N] (opts.choiceTag), and **NOT** the type tag
			var explicitID byte
			if opts.choiceTag != nil {
				explicitID = byte(opts.Class()<<6) | 0x20 | byte((*opts.choiceTag))
			}
			sub.Append(explicitID)
			lenBytes := encodeLength(sub.Type(), len(innerEnc))
			sub.Append(lenBytes...)
			sub.Append(innerEnc...)
		}
	}

	return
}

/*
unmarshalSequence returns an error following an attempt to write pkt into sequence (struct) v.
*/
func unmarshalSequence(v reflect.Value, pkt Packet, options ...Options) (err error) {

	var tlv TLV
	if tlv, err = pkt.TLV(); err != nil {
		err = mkerr("unmarshalValue: reading SEQUENCE TL header failed: " + err.Error())
		return
	}

	start := pkt.Offset()
	end := start + tlv.Length
	if end > len(pkt.Data()) {
		err = mkerr("unmarshalValue: insufficient data for SEQUENCE content")
		return
	}

	seqContent := pkt.Data()[start:end]
	pkt.SetOffset(end)
	sub := pkt.Type().New(seqContent...)
	defer sub.Free()
	sub.SetOffset(0)

	typ := v.Type()
	for i := 0; i < v.NumField() && err == nil; i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}

		var opts Options = implicitOptions()
		if field.Tag != "" {
			if opts, err = extractOptions(field); err != nil {
				return
			}
		}

		fv := v.Field(i)
		switch fv.Interface().(type) {
		case Choice, *Choice:
			var alt Choice
			if alt, err = callChoicesMethod(field.Name, v.Interface(), sub, opts); err == nil {
				fv.Set(reflect.ValueOf(Choice{Value: alt.Value}))
			}
		default:
			if err = unmarshalValue(sub, fv, opts); err != nil {
				if !opts.Optional {
					err = mkerr("unmarshalValue: failed for field " + field.Name + ": " + err.Error())
				} else {
					err = nil // if optional, discard error
				}
			}
		}
	}

	return
}
