package asn1plus

/*
runtime.go contains the exported package-level encoding/decoding
functions and associated private helpers.
*/

import "reflect"

/*
Marshal returns an instance of [PDU] alongside an error following an attempt
to encode x using the specified ASN.1 encoding.

The variadic [EncodingOption] input value is used to further user control using
one or more of:

  - [EncodingRule] (e.g.: [BER], [DER])
  - [EncodingOption] (e.g.: to declare a value to be of an INDEFINITE-LENGTH, or for a class override)

If an [EncodingRule] is not specified, the value of [DefaultEncoding] is used,
which is [BER] by default.

See also [Unmarshal] and [With].
*/
func Marshal(x any, with ...EncodingOption) (pkt PDU, err error) {
	cfg := &encodingConfig{rule: DefaultEncoding}
	for _, o := range with {
		o(cfg)
	}

	li := newLItem(err)
	debugEnter(x, cfg.rule, cfg.opts)
	defer func() {
		debugExit(pkt, &li)
	}()

	if err = marshalCheckBadOptions(cfg.rule, cfg.opts); err == nil {
		cfg.opts = marshalPrepareSpecialOptions(x, cfg.opts)
		pkt = cfg.rule.New()
		err = marshalValue(refValueOf(x), pkt, cfg.opts)
	}

	return
}

/*
marshalSpecial returns the input instance of *[Options], but modified
to contain special encoding directives for certain types defined within
this package (such as EmbeddedPDV) to honor official ASN.1 schema
definitions described in ITU-T recommendations, RFCs, et al.

Essentially, this is a quick way to prevent a special constructed type
from being wrongly encoded as an ordinary SEQUENCE.
*/
func marshalPrepareSpecialOptions(v any, o *Options) (opts *Options) {
	debugEnter(v, o)
	defer func() {
		debugExit(opts)
	}()

	var override *Options

	var match bool
	if override, match = embeddedPDVOrExternalSpecial(v); !match {
		opts = o
		return
	}

	if o == nil {
		opts = override
	} else {
		o.SetClass(override.Class())
		o.SetTag(override.Tag())
		opts = o
	}

	return
}

/*
marshalCheckBadOptions returns an error following a scan for illegal or
unsupported options statements just prior to the marshaling process.
*/
func marshalCheckBadOptions(rule EncodingRule, o *Options) (err error) {
	debugEnter(rule, o)
	defer func() {
		debugExit(newLItem(err))
	}()

	if o != nil {
		if !rule.allowsIndefinite() && o.Indefinite {
			err = mkerrf("Use of INDEFINITE-LENGTH is incompatible with encoding rule ", rule.String())
		}
	}

	return
}

func marshalValue(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, pkt, opts)
	defer func() {
		debugExit(newLItem(err))
	}()

	// Guard against zero reflect.Value
	if !v.IsValid() {
		return mkerr("marshalValue: invalid or nil value")
	}

	oopts, _ := lookupOverrideOptions(v.Interface())
	if oopts != nil {
		opts = oopts
		debugEvent(EventTrace, newLItem(opts, "override options"))
	}

	// Handle pointers first
	if v.Kind() == reflect.Ptr {
		return marshalValue(v.Elem(), pkt, opts)
	}

	//  Detect Choice on interface *before* unwrapping
	if v.Kind() == reflect.Interface {
		if !v.IsNil() && v.CanInterface() {
			if _, ok := v.Interface().(Choice); ok {
				// ensure opts isn’t nil, so marshalChoiceWrapper never sees nil opts
				return marshalChoiceWrapper(nil, pkt, deferImplicit(opts), v)
			}
		}
		// not a Choice interface, so peel and recurse
		return marshalValue(v.Elem(), pkt, opts)
	}

	// Detect Choice on concrete value
	if v.CanInterface() {
		if _, ok := v.Interface().(Choice); ok {
			opts = deferImplicit(opts)
			return marshalChoiceWrapper(nil, pkt, opts, v)
		}
	}

	// Wrap any concrete type registered in any interface-family
	var handled bool

	if handled, err = marshalInterfaceChoice(v, pkt, opts); handled {
		return
	}

	switch {
	case v.Kind() == reflect.Invalid:
		err = codecErrorf("Nil value passed to Marshal")
		return
	case ptrIsNil(v):
		err = codecErrorf("Marshal: input must be non-nil")
		return
	}
	v = derefValuePtr(v)

	for _, funk := range []func(reflect.Value, PDU, *Options) (bool, error){
		marshalChoice,     // Choice (recursion) path
		marshalPrimitive,  // ASN.1 Primitive path
		marshalViaAdapter, // Adapter path
	} {
		if handled, err = funk(v, pkt, opts); handled {
			return
		}
	}

	err = marshalComposite(v, pkt, opts)
	pkt.SetOffset(0)

	return
}

// CHOICE unwrap
func marshalChoice(v reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {
	if handled = isChoice(v, opts); handled {
		err = marshalChoiceWrapper(nil, pkt, opts, v)
	}
	return
}

func marshalComposite(v reflect.Value, pkt PDU, opts *Options) (err error) {
	switch v.Kind() {
	case reflect.Slice:
		opts.incDepth()
		if opts != nil && opts.Sequence {
			err = marshalSequenceOfSlice(v, pkt, opts)
		} else {
			err = marshalSet(v, pkt, opts)
		}
	case reflect.Struct:
		opts.incDepth()
		err = marshalSequence(v, pkt, opts)
	default:
		err = mkerrf("marshalValue: unsupported type ", v.Kind().String())
	}

	return
}

func marshalInterfaceChoice(v reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {
	if opts != nil && opts.Choices != "" {
		typ := pkt.Type()
		reg, _ := GetChoices(opts.Choices)

		concreteT := v.Type()
		var desc *choiceDescriptor
		if _, desc, handled = reg.lookupDescriptorByConcrete(concreteT); handled {
			tag := desc.typeToTag[concreteT]
			cls := desc.class[tag]
			exp := desc.explicit[tag]

			tmp := typ.New()
			tmp.SetOffset(0)

			switch v.Kind() {
			case reflect.Slice:
				if opts.Sequence {
					err = marshalSequenceOfSlice(v, tmp, opts)
				} else {
					err = marshalSet(v, tmp, opts)
				}
			case reflect.Struct:
				err = marshalSequence(v, tmp, opts)
			default:
				opts.Choices = ""
				err = marshalValue(v, tmp, opts)
			}

			if err == nil {
				ntlv := typ.newTLV(cls, tag, tmp.Len(), exp, tmp.Data()...)
				pkt.WriteTLV(ntlv)
			}
		}
	}

	return
}

func marshalViaAdapter(v reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {

	opts = deferImplicit(opts)
	kw := opts.Identifier

	var ad adapter
	if ad, handled = adapterForValue(v, kw); !handled {
		return
	}

	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(handled, "adapter handled"), newLItem(err))
	}()
	codec := ad.newCodec()

	if err = ad.fromGo(v.Interface(), codec, opts); err != nil {
		return
	}

	if opts.Explicit {
		err = wrapMarshalExplicit(pkt, codec.(codecRW), opts)
	} else {
		_, err = codec.(codecRW).write(pkt, opts)
	}

	return
}

func marshalPrimitive(v reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {
	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(handled, "primitive handled"), newLItem(err))
	}()

	if !isPrimitive(v.Interface()) {
		return false, nil
	}

	opts = deferImplicit(opts)
	raw := toPtr(v).Interface()

	if c, ok := raw.(codecRW); ok {
		// Prefer the value’s own codec implementation
		handled = true
		if opts.Explicit {
			err = wrapMarshalExplicit(pkt, c, opts)
		} else {
			_, err = c.write(pkt, opts)
		}
	} else if bx, ok := createCodecForPrimitive(raw); ok {
		// Legacy pointer – build a codec on the fly
		handled = true
		if opts.Explicit {
			err = wrapMarshalExplicit(pkt, bx, opts)
		} else {
			_, err = bx.write(pkt, opts)
		}
	} else {
		err = mkerr("no codec found for primitive")
	}

	return
}

func wrapMarshalExplicit(pkt PDU, prim codecRW, opts *Options) (err error) {
	debugEnter(prim, opts, pkt)
	defer func() {
		debugExit(newLItem(err))
	}()

	typ := pkt.Type()
	tmp := typ.New()
	innerOpts := clearChildOpts(opts)

	if _, err = prim.write(tmp, innerOpts); err == nil {
		content := tmp.Data()
		id := emitHeader(opts.Class(), opts.Tag(), true)
		debugPrim(newLItem(id, "EXPLICIT tag"))
		pkt.Append(id)
		bufPtr := getBuf()
		lcont := len(content)
		encodeLengthInto(typ, bufPtr, lcont)
		pkt.Append(*bufPtr...)
		putBuf(bufPtr)
		pkt.Append(content...)
	}

	return
}

/*
Unmarshal returns an error following an attempt to decode the input [PDU] instance
into x. x MUST be a pointer.

The variadic [EncodingOption] input value allows for [Options] directives meant to
further control the decoding process.

It is not necessary to declare a particular [EncodingRule] using the [With] package-level
function, as the input instance of [PDU] already has this information. Providing an
[EncodingRule] to Unmarshal -- whether valid or not -- will produce no perceptible effect.

See also [Marshal] and [With].
*/
func Unmarshal(pkt PDU, x any, with ...EncodingOption) error {
	rv := refValueOf(x)
	var err error

	debugEnter(x, with, pkt)
	defer func() {
		debugExit(newLItem(err))
	}()

	// Validate that target x is a non-nil pointer.
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		err = mkerr("Unmarshal: target must be a non-nil pointer")
		return err
	}

	pkt.SetOffset(0)

	cfg := &encodingConfig{rule: pkt.Type()}
	for _, o := range with {
		o(cfg)
	}

	if cfg.opts != nil {
		err = unmarshalValue(pkt, rv.Elem(), cfg.opts)
	} else {
		err = unmarshalValue(pkt, rv.Elem(), nil)
	}

	return err
}

/*
unmarshalValue returns an error following an attempt to decode v into pkt, possibly
aided by [Options] directives.

This function is called by the top-level Unmarshal function, as well as certain low
level functions via recursion.
*/
func unmarshalValue(pkt PDU, v reflect.Value, opts *Options) (err error) {
	oopts, _ := lookupOverrideOptions(v.Interface())
	if oopts != nil {
		opts = oopts
	}

	if isInterfaceChoice(v, opts) {
		err = unmarshalChoice(v, pkt, opts)
		return
	}

	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(err))
	}()

	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			err = mkerr("unmarshalValue: input pointer is nil")
			return
		}
		v = v.Elem()
	} else if v.Kind() == reflect.Invalid {
		err = mkerr("unmarshalValue: input pointer is invalid")
		return
	}

	opts = deferImplicit(opts)
	kw := opts.Identifier

	if ad, ok := adapterForValue(v, kw); ok {
		codec := ad.newCodec()
		var tlv TLV
		if tlv, err = pkt.TLV(); err != nil {
			return
		}

		outerLen := tlv.Length
		start := pkt.Offset()

		if err = unmarshalHandleTag(kw, pkt, &tlv, opts); err != nil {
			return
		}
		if err = codec.(codecRW).read(pkt, tlv, opts); err != nil {
			return
		}
		pkt.SetOffset(start + outerLen)

		goVal := refValueOf(ad.toGo(codec))
		if !goVal.Type().AssignableTo(v.Type()) {
			err = mkerrf("type mismatch decoding ", kw)
		} else {
			err = refSetValue(v, goVal)
		}
		return
	}

	if val := v.Interface(); isPrimitive(val) {
		err = unmarshalPrimitive(pkt, v, opts)
		return
	}

	switch v.Kind() {
	case reflect.Slice:
		if opts.Sequence {
			err = unmarshalSequenceBranch(v, pkt, opts)
		} else {
			err = unmarshalSetBranch(v, pkt, opts)
		}
	case reflect.Struct:
		err = unmarshalSequence(v, pkt, opts)
	default:
		err = mkerrf("unmarshalValue: unsupported type ", v.Kind().String())
	}
	return
}

func unmarshalChoice(v reflect.Value, pkt PDU, opts *Options) error {
	// strip the [n] EXPLICIT header
	tag, _, sub, chopts, err := setPickChoiceAlternative(pkt, opts)
	if err != nil {
		return err
	}

	// lookup the descriptor by wire‐tag
	reg, _ := GetChoices(opts.Choices)
	_, cd, ok := reg.lookupDescriptorByTag(tag)
	if !ok {
		return mkerrf("CHOICE tag not registered: ", itoa(tag))
	}

	// decode into the concrete Go value
	inner := reflect.New(cd.tagToType[tag]).Elem()
	if err = unmarshalValue(sub, inner, chopts); err != nil {
		return mkerrf(
			"decodeCtxChoice[", cd.tagToType[tag].String(),
			"]: ", err.Error(),
		)
	}

	// ALWAYS wrap back into the Choice interface
	choiceType := refTypeOf((*Choice)(nil)).Elem()
	if v.Type() == choiceType {
		ch := refValueOf(NewChoice(inner.Interface(), tag))
		err = refSetValue(v, ch)
	} else {
		err = refSetValue(v, inner)
	}
	return err
}

func unmarshalSequenceBranch(v reflect.Value, pkt PDU, opts *Options) (err error) {
	var tlv TLV
	if tlv, err = pkt.TLV(); err != nil {
		err = mkerrf("unmarshalSequenceBranch: no SEQUENCE header: ", err.Error())
		return
	}
	if tlv.Class != ClassUniversal || tlv.Tag != TagSequence {
		err = mkerrf("expected SEQUENCE (16); got ", itoa(tlv.Class), "/", itoa(tlv.Tag))
		return
	}
	start := pkt.Offset()
	end := start + tlv.Length
	if end > pkt.Len() {
		err = mkerr("unmarshalSequenceBranch: truncated content")
		return
	}

	data := pkt.Data()[start:end]
	pkt.SetOffset(end)

	sub := pkt.Type().New(data...)
	sub.SetOffset(0)

	elemOpts := *opts
	elemOpts.Sequence = false

	elemType := v.Type().Elem()
	for sub.Offset() < len(data) {
		// create a zero‐value element
		elem := refNew(elemType).Elem()
		if err = unmarshalValue(sub, elem, &elemOpts); err != nil {
			err = mkerrf("unmarshalSequenceBranch: element decode failed: ", err.Error())
			return
		}
		if err = refSetValue(v, reflect.Append(v, elem)); err != nil {
			return
		}
	}

	return
}

func unmarshalSetBranch(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() { debugExit(newLItem(err)) }()

	typ := pkt.Type()

	// If this slice is actually SET OF CHOICE
	if opts != nil && opts.Choices != "" {
		reg, ok := GetChoices(opts.Choices)
		if !ok {
			err = mkerrf("no CHOICE registry ", opts.Choices)
			return
		}

		// look up the *choiceDescriptor* registered for OctetString
		elemType := v.Type().Elem()
		cd, ok := reg.reg[elemType] // <- use the type as key
		if !ok {
			return mkerrf("unmarshalSetBranch: no descriptor for type ", elemType.String())
		}

		// consume the SET‐OF wrapper
		var outer TLV
		if outer, err = pkt.TLV(); err != nil {
			return
		}
		pkt.AddOffset(outer.Length)
		sub := typ.New(outer.Value...)
		sub.SetOffset(0)

		result := refMkSl(v.Type(), 0, 0)

		// for each [n] EXPLICIT element
		for sub.HasMoreData() {
			tag, _, childPK, childOpts, e := setPickChoiceAlternative(sub, opts)
			if e != nil {
				err = e
				return
			}

			// find the Go type for that tag
			childType, found := cd.tagToType[tag]
			if !found {
				err = mkerrf("CHOICE tag ", itoa(tag), " not registered")
				return
			}

			// decode into the concrete type
			innerVal := refNew(childType).Elem()
			if err = unmarshalValue(childPK, innerVal, childOpts); err != nil {
				return
			}

			// convert and append
			result = reflect.Append(result, innerVal.Convert(elemType))
		}

		err = refSetValue(v, result)
		return
	}

	// otherwise your original SET logic
	if opts != nil && (opts.HasTag() || opts.Class() != ClassUniversal) {
		var outer TLV
		if outer, err = pkt.TLV(); err == nil {
			hdrEnd := pkt.Offset()
			subPkt := typ.New(outer.Value...)
			subPkt.SetOffset(0)
			if err = unmarshalSet(v, subPkt, opts); err == nil {
				pkt.SetOffset(hdrEnd + len(outer.Value))
			}
		}
	} else {
		err = unmarshalSet(v, pkt, opts)
	}

	return
}

func unmarshalPrimitive(pkt PDU, v reflect.Value, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(err))
	}()

	var tlv TLV
	var start int
	if tlv, err = pkt.TLV(); err == nil {
		start = pkt.Offset()

		// The pointer itself is a codec
		if c, ok := toPtr(v).Interface().(codecRW); ok {
			err = c.read(pkt, tlv, opts)
		} else if bx, ok := createCodecForPrimitive(v.Interface()); ok { // Path 2: build codec
			if err = bx.read(pkt, tlv, opts); err == nil {
				err = refSetValue(v, refValueOf(bx.getVal()))
			}
		} else {
			err = mkerr("no codec for primitive")
		}
	}

	if err == nil {
		pkt.SetOffset(start + tlv.Length)
	}
	return
}

func unmarshalHandleTag(kw string, pkt PDU, tlv *TLV, opts *Options) (err error) {
	debugEnter(newLItem(kw, "keyword", tlv, opts, pkt))
	defer func() {
		debugExit(newLItem(err))
	}()

	opts = deferImplicit(opts)
	if opts.HasTag() {
		if tlv.Class != opts.Class() || tlv.Tag != opts.Tag() {
			err = mkerrf("identifier mismatch decoding ", kw)
		} else if opts.Explicit {
			inner := pkt.Type().New()
			// TODO: determine why this is necessary (else, breaks
			// "TestSequence_FieldsExplicit" via New(tlv.Value...))
			inner.Append(tlv.Value...)
			var innerTLV TLV
			if innerTLV, err = inner.TLV(); err == nil {
				*tlv = innerTLV
				opts.Explicit = false
				opts.tag = nil
				opts.class = nil
			}
		}
	}

	return
}
