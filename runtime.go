package asn1plus

/*
runtime.go contains the exported package-level encoding/decoding
functions and associated private helpers.
*/

import "reflect"

/*
Marshal returns an instance of [Packet] alongside an error following an attempt
to encode x using the specified ASN.1 encoding.

The variadic [EncodingOption] input value is used to further user control using
one or more of:

  - [EncodingRule] (e.g.: [BER], [DER])
  - [EncodingOption] (e.g.: to declare a value to be of an INDEFINITE-LENGTH, or for a class override)

If an encoding rule is not specified, [DER] encoding is used as the default.

See also [Unmarshal] and [With].
*/
func Marshal(x any, with ...EncodingOption) (pkt Packet, err error) {
	// For example, we default to DER and to a default Options value.
	cfg := &encodingConfig{
		rule: DER,
	}

	for _, o := range with {
		o(cfg)
	}

	if err = checkBadMarshalOptions(cfg.rule, cfg.opts); err == nil {
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
func marshalPrepareSpecialOptions(v any, o *Options) *Options {
	var override *Options

	switch v.(type) {
	case EmbeddedPDV, *EmbeddedPDV:
		override = embeddedPDVSpecial()
	case External, *External:
		override = externalSpecial()
	default:
		return o
	}

	if o == nil {
		o = override
	} else {
		o.SetClass(override.Class())
		o.SetTag(override.Tag())
	}

	return o
}

/*
checkBadMarshalOptions returns an error following a scan for illegal or
unsupported options statements just prior to the marshaling process.
*/
func checkBadMarshalOptions(rule EncodingRule, o *Options) (err error) {
	if o != nil {
		if rule != BER && o.Indefinite {
			err = mkerrf("Use of INDEFINITE-LENGTH is incompatible with encoding rule ", rule.String())
		}
	}

	return
}

func marshalValue(v reflect.Value, pkt Packet, opts *Options, depth int) error {
	switch {
	case v.Kind() == reflect.Invalid:
		return mkerr("Nil value passed to Marshal")
	case v.Kind() == reflect.Ptr && v.IsNil():
		return mkerr("Marshal: input must be non-nil")
	case v.Kind() == reflect.Ptr:
		v = v.Elem()
	}

	// CHOICE unwrap
	if ch, ok := v.Interface().(Choice); ok {
		if !ch.Explicit {
			return marshalValue(reflect.ValueOf(ch.Value), pkt, opts, depth+1)
		} else if ch.Tag == nil {
			return mkerr("choice tag undefined")
		}

		tmp := pkt.Type().New()

		if err := marshalValue(reflect.ValueOf(ch.Value), tmp, opts, depth+1); err != nil {
			return err
		}
		inner := tmp.Data()

		id := byte(ClassContextSpecific<<6) | 0x20 | byte(*ch.Tag)
		pkt.Append(id)
		pkt.Append(encodeLength(pkt.Type(), len(inner))...)
		pkt.Append(inner...)
		return nil
	}

	// Adapter path
	if done, err := marshalViaAdapter(v, pkt, opts); done {
		return err
	}

	// Primitive path
	if done, err := marshalPrimitive(v, pkt, opts); done {
		return err
	}

	// Composite types
	var err error
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

func marshalViaAdapter(v reflect.Value, pkt Packet, opts *Options) (handled bool, err error) {
	kw := ""
	if opts != nil {
		kw = opts.Identifier
	} else {
		opts = implicitOptions()
	}

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

func marshalPrimitive(v reflect.Value, pkt Packet, opts *Options) (handled bool, err error) {
	if !isPrimitive(v.Interface()) {
		return false, nil
	}
	if opts == nil {
		opts = implicitOptions()
	}

	raw := toPtr(v).Interface() // *T or value T

	// Prefer the value’s own codec implementation
	if c, ok := raw.(codecRW); ok {
		if opts.Explicit {
			return true, wrapMarshalExplicit(pkt, c, opts)
		}
		_, err := c.write(pkt, opts)
		return true, err
	}

	// Legacy pointer – build a codec on the fly
	if bx, ok := createCodecForPrimitive(raw); ok {
		if opts.Explicit {
			return true, wrapMarshalExplicit(pkt, bx, opts)
		}
		_, err := bx.write(pkt, opts)
		return true, err
	}

	return false, mkerr("no codec for primitive")
}

func wrapMarshalExplicit(pkt Packet, prim codecRW, opts *Options) (err error) {
	tmp := pkt.Type().New()
	innerOpts := *opts
	innerOpts.Explicit = false
	innerOpts.tag = nil
	innerOpts.class = nil

	if _, err = prim.write(tmp, &innerOpts); err == nil {
		content := tmp.Data()

		id := byte(opts.Class()<<6) | 0x20 | byte(opts.Tag())
		pkt.Append(id)
		pkt.Append(encodeLength(pkt.Type(), len(content))...)
		pkt.Append(content...)
	}

	return
}

/*
Unmarshal returns an error following an attempt to decode the input [Packet] instance
into x. x MUST be a pointer.

The variadic [EncodingOption] input value allows for [Options] directives meant to
further control the decoding process.

It is not necessary to declare a particular [EncodingRule] using the [With] package-level
function, as the input instance of [Packet] already has this information. Providing an
[EncodingRule] to Unmarshal -- whether valid or not -- will produce no perceptible effect.

See also [Marshal] and [With].
*/
func Unmarshal(pkt Packet, x any, with ...EncodingOption) error {
	rv := reflect.ValueOf(x)
	var err error

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
func unmarshalValue(pkt Packet, v reflect.Value, options *Options) (err error) {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			err = mkerr("unmarshalValue: input pointer is nil")
			return
		}
		v = v.Elem()
	}

	kw := ""
	opts := implicitOptions()
	if options != nil {
		opts = options
		kw = opts.Identifier
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
		err = unmarshalSet(v, pkt, opts)
	case reflect.Struct:
		err = unmarshalSequence(v, pkt, opts)
	default:
		err = mkerrf("unmarshalValue: unsupported type ", v.Kind().String())
	}

	return
}

func unmarshalPrimitive(pkt Packet, v reflect.Value, opts *Options) (err error) {
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

func unmarshalHandleTag(kw string, pkt Packet, tlv *TLV, opts *Options) (err error) {
	if opts == nil {
		opts = implicitOptions()
	}
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
