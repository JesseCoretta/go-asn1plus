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
  - [Options] (e.g.: to declare a value to be of an INDEFINITE-LENGTH, or for a class override.

If an encoding rule is not specified, [DER] encoding is used as the default.

See also [Unmarshal].
*/
func Marshal(x any, options ...EncodingOption) (pkt Packet, err error) {
	// For example, we default to DER and to a default Options value.
	cfg := &encodingConfig{
		rule: DER,
	}

	for _, o := range options {
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
			err = mkerr("Use of INDEFINITE-LENGTH is incompatible with encoding rule " + rule.String())
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
		return marshalValue(reflect.ValueOf(ch.Value), pkt, opts, depth)
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
		err = mkerr("marshalValue: unsupported type " + v.Kind().String())
	}
	pkt.SetOffset(0)
	return err
}

func marshalViaAdapter(v reflect.Value, pkt Packet, opts *Options) (handled bool, err error) {
	kw := ""
	if opts != nil {
		kw = opts.Identifier
	}

	ad, ok := adapterForValue(v, kw)
	if !ok {
		return false, nil
	}

	codec := ad.newCodec()
	if err = ad.fromGo(v.Interface(), codec, *opts); err != nil {
		return true, err
	}

	if opts.Explicit {
		err = wrapMarshalExplicit(pkt, codec.(Primitive), opts)
	} else {
		_, err = codec.(Primitive).write(pkt, *opts)
	}

	return true, err
}

func marshalPrimitive(v reflect.Value, pkt Packet, opts *Options) (handled bool, err error) {
	if !isPrimitive(v.Interface()) {
		return false, nil
	}

	// Ensure we have an Options object.
	if opts == nil {
		tmp := implicitOptions()
		opts = &tmp
	}

	prim := toPtr(v).Interface().(Primitive)
	if opts.Explicit {
		err = wrapMarshalExplicit(pkt, prim, opts)
	} else {
		_, err = prim.write(pkt, *opts)
	}
	return true, err
}

func wrapMarshalExplicit(pkt Packet, prim Primitive, opts *Options) (err error) {
	tmp := pkt.Type().New()
	defer tmp.Free()

	innerOpts := *opts
	innerOpts.Explicit = false
	innerOpts.tag = nil
	innerOpts.class = nil

	if _, err = prim.write(tmp, innerOpts); err == nil {
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

It is not necessary to declare a particular [EncodingRule] using the [WithEncoding]
package-level function, as the input instance of [Packet] already has this information.
Providing an [EncodingRule] to Unmarshal -- whether valid or not -- will produce no
perceptible effect.

See also [Marshal].
*/
func Unmarshal(pkt Packet, x any, options ...EncodingOption) error {
	rv := reflect.ValueOf(x)
	var err error
	// Validate that target x is a non-nil pointer.
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		err = mkerr("Unmarshal: target must be a non-nil pointer")
		return err
	}

	pkt.SetOffset(0)

	cfg := &encodingConfig{rule: pkt.Type()}
	for _, o := range options {
		o(cfg)
	}

	if cfg.opts != nil {
		err = unmarshalValue(pkt, rv.Elem(), (*cfg.opts))
	} else {
		err = unmarshalValue(pkt, rv.Elem())
	}

	return err
}

/*
unmarshalValue returns an error following an attempt to decode v into pkt, possibly
aided by [Options] directives.

This function is called by the top-level Unmarshal function, as well as certain low
level functions via recursion.
*/
func unmarshalValue(pkt Packet, v reflect.Value, options ...Options) (err error) {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			err = mkerr("unmarshalValue: input pointer is nil")
			return
		}
		v = v.Elem()
	}

	kw := ""
	if len(options) > 0 {
		kw = options[0].Identifier
	}

	opts := implicitOptions()
	if len(options) > 0 {
		opts = options[0]
	}

	if ad, ok := adapterForValue(v, kw); ok {
		codec := ad.newCodec()

		var tlv TLV
		if tlv, err = pkt.TLV(); err != nil {
			return
		}

		start := pkt.Offset()

		if err = unmarshalHandleTag(kw, pkt, opts, tlv); err != nil {
			return
		}

		if err = codec.(Primitive).read(pkt, tlv, opts); err != nil {
			return
		}
		pkt.SetOffset(start + tlv.Length)

		goVal := reflect.ValueOf(ad.toGo(codec))
		if !goVal.Type().AssignableTo(v.Type()) {
			err = mkerr("type mismatch decoding " + kw)
			return
		}
		v.Set(goVal)
		return
	}

	if val := v.Interface(); isPrimitive(val) {
		var tlv TLV
		if tlv, err = pkt.TLV(); err != nil {
			err = mkerr("unmarshalValue: failed reading tag/length for primitive: " + err.Error())
			return
		}
		startOffset := pkt.Offset()
		if err = toPtr(v).Interface().(Primitive).read(pkt, tlv, opts); err == nil {
			pkt.SetOffset(startOffset + tlv.Length)
		}
		return
	}

	switch v.Kind() {
	case reflect.Slice:
		return unmarshalSet(v, pkt, options...)
	case reflect.Struct:
		return unmarshalSequence(v, pkt, options...)
	default:
		return mkerr("unmarshalValue: unsupported type " + v.Kind().String())
	}
}

func unmarshalHandleTag(kw string, pkt Packet, opts Options, tlv TLV) (err error) {
	if opts.HasTag() {
		if tlv.Class != opts.Class() || tlv.Tag != opts.Tag() {
			err = mkerr("identifier mismatch decoding " + kw)
		} else if opts.Explicit {
			inner := pkt.Type().New()
			inner.Append(tlv.Value...)
			if tlv, err = inner.TLV(); err == nil {
				pkt = inner
				opts.Explicit = false
				opts.tag = nil
				opts.class = nil
			}
		}
	}

	return
}
