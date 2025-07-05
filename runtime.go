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
which is [DER] by default.

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
		err = marshalValue(reflect.ValueOf(x), pkt, cfg.opts, 0)
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

func marshalValue(v reflect.Value, pkt PDU, opts *Options, depth int) (err error) {
	defer debugPath(v, opts, newLItem(depth, "depth"))(newLItem(err))

	switch {
	case v.Kind() == reflect.Invalid:
		err = mkerr("Nil value passed to Marshal")
		return
	case v.Kind() == reflect.Ptr && v.IsNil():
		err = mkerr("Marshal: input must be non-nil")
		return
	}
	v = derefValuePtr(v)

	// CHOICE unwrap
	if ch, ok := v.Interface().(Choice); ok {
		debugChoice(ch)
		chv := refValueOf(ch.Value)
		if !ch.Explicit {
			err = marshalValue(chv, pkt, opts, depth+1)
			debugChoice(ch, newLItem(err))
			return
		} else if ch.Tag == nil {
			err = mkerr("choice tag undefined")
			debugChoice(ch, newLItem(err))
			return
		}

		tmp := pkt.Type().New()
		debugTrace(newLItem(tmp, "ALLOC::"+pkt.Type().String()))

		if err = marshalValue(chv, tmp, opts, depth+1); err == nil {
			inner := tmp.Data()
			cht := *ch.Tag
			id := byte(ClassContextSpecific<<6) | 0x20 | byte(cht)
			debugChoice(newLItem(id, "CHOICE tag"))
			pkt.Append(id)
			bufPtr := getBuf()
			encodeLengthInto(pkt.Type(), bufPtr, len(inner))
			pkt.Append(*bufPtr...)
			putBuf(bufPtr)
			pkt.Append(inner...)
			debugTrace(newLItem(inner, "APPEND::"+pkt.Type().String()))
		}
		return
	}

	var handled bool

	// Primitive path
	if handled, err = marshalPrimitive(v, pkt, opts); handled {
		return err
	}

	// Adapter path
	if handled, err = marshalViaAdapter(v, pkt, opts); handled {
		return err
	}

	// Composite types
	switch v.Kind() {
	case reflect.Slice:
		err = marshalSet(v, pkt, opts, depth+1)
	case reflect.Struct:
		err = marshalSequence(v, pkt, opts, depth+1)
	default:
		err = mkerrf("marshalValue: unsupported type ", v.Kind().String())
	}
	pkt.SetOffset(0)
	return err
}

func marshalViaAdapter(v reflect.Value, pkt PDU, opts *Options) (handled bool, err error) {
	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(handled, "adapter handled"), newLItem(err))
	}()

	opts = deferImplicit(opts)
	kw := opts.Identifier

	ad, ok := adapterForValue(v, kw)
	if !ok {
		return false, nil
	}
	codec := ad.newCodec()

	if err = ad.fromGo(v.Interface(), codec, opts); err != nil {
		return true, err
	}

	if opts.Explicit {
		err = wrapMarshalExplicit(pkt, codec.(codecRW), opts)
	} else {
		_, err = codec.(codecRW).write(pkt, opts)
	}

	return true, err
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

	tmp := pkt.Type().New()
	innerOpts := *opts
	innerOpts.Explicit = false
	innerOpts.tag = nil
	innerOpts.class = nil

	if _, err = prim.write(tmp, &innerOpts); err == nil {
		content := tmp.Data()

		id := byte(opts.Class()<<6) | 0x20 | byte(opts.Tag())
		debugPrim(newLItem(id, "EXPLICIT tag"))
		pkt.Append(id)
		bufPtr := getBuf()
		lcont := len(content)
		encodeLengthInto(pkt.Type(), bufPtr, lcont)
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
	rv := reflect.ValueOf(x)
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
	}

	v = unwrapInterface(v)

	opts = deferImplicit(opts)
	kw := opts.Identifier

	if v.Type() == reflect.TypeOf(Choice{}) {
		var alt Choice
		if alt, err = selectFieldChoice("", struct{}{}, pkt, opts); err == nil {
			v.Set(reflect.ValueOf(alt))
		}
		return
	}

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

		goVal := reflect.ValueOf(ad.toGo(codec))
		if !goVal.Type().AssignableTo(v.Type()) {
			err = mkerrf("type mismatch decoding ", kw)
			return
		}
		v.Set(goVal)
		return
	}

	if val := v.Interface(); isPrimitive(val) {
		return unmarshalPrimitive(pkt, v, opts)
	}

	switch v.Kind() {
	case reflect.Slice:
		err = unmarshalSetBranch(v, pkt, opts)
	case reflect.Struct:
		err = unmarshalSequence(v, pkt, opts)
	default:
		err = mkerrf("unmarshalValue: unsupported type ", v.Kind().String())
	}

	return
}

func unmarshalSetBranch(v reflect.Value, pkt PDU, opts *Options) (err error) {
	debugEnter(v, opts, pkt)
	defer func() {
		debugExit(newLItem(err))
	}()

	if opts != nil && (opts.HasTag() || opts.Class() != ClassUniversal) {
		var outer TLV
		if outer, err = pkt.TLV(); err == nil {
			hdrEnd := pkt.Offset()
			subPkt := pkt.Type().New(outer.Value...)
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
				v.Set(reflect.ValueOf(bx.getVal()))
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
