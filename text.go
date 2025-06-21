package asn1plus

/*
str.go contains all types and methods pertaining to the registration
and use of all string/[]byte type derivatives.
*/

import "reflect"

/*
TextLike is implemented through string and []byte types,
which represent the predominant type forms of most ASN.1
primitives defined throughout this package.
*/
type TextLike interface{ ~string | ~[]byte }

type textCodec[T TextLike] struct {
	val          T
	tag          int
	cg           ConstraintGroup[T]
	decodeVerify []DecodeVerifier
	decodeHook   DecodeOverride[T]
	encodeHook   EncodeOverride[T]
}

func (c *textCodec[T]) Tag() int          { return c.tag }
func (c *textCodec[T]) String() string    { return "textCodec" }
func (c *textCodec[T]) IsPrimitive() bool { return true }
func (c *textCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }
func (c *textCodec[T]) getVal() any       { return c.val }

func (c *textCodec[T]) write(pkt Packet, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, DER:
		n, err = bcdTextWrite[T](c, pkt, o)
	case CER:
		if len([]byte(c.val)) > 1000 && c.Tag() == TagOctetString {
			n, err = cerSegmentedOctetStringWrite(c, pkt, o)
		} else {
			n, err = bcdTextWrite[T](c, pkt, o)
		}
	default:
		err = errorRuleNotImplemented
	}

	return
}

func bcdTextWrite[T TextLike](c *textCodec[T], pkt Packet, o *Options) (off int, err error) {
	o = deferImplicit(o)

	if err = c.cg.Constrain(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			wire = []byte(c.val)
		}

		if err == nil {
			tag, cls := effectiveTag(c.tag, 0, o)
			start := pkt.Offset()
			err = writeTLV(pkt, pkt.Type().newTLV(cls, tag, len(wire), false, wire...), o)
			if err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *textCodec[T]) read(pkt Packet, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, DER:
		err = bcdTextRead(c, pkt, tlv, o)
	case CER:
		if tlv.Compound && tlv.Length < 0 && c.Tag() == TagOctetString {
			err = cerSegmentedOctetStringRead(c, pkt, o)
		} else {
			err = bcdTextRead(c, pkt, tlv, o)
		}
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdTextRead[T TextLike](c *textCodec[T], pkt Packet, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {
		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		var val T
		if err = decodeVerify(); err == nil {
			if c.decodeHook != nil {
				val, err = c.decodeHook(wire)
			} else {
				val = T(append([]byte(nil), wire...))
			}

			if err == nil {
				if err = c.cg.Constrain(val); err == nil {
					c.val = val
					pkt.SetOffset(pkt.Offset() + tlv.Length)
				}
			}
		}
	}

	return err
}

/*
DecodeVerifier allows the implementation of a function check
meant to examine encoded bytes prior to the decoding process.

This is only intended for advanced corner-cases and most often
need not be used.
*/
type DecodeVerifier func([]byte) error

/*
DecodeOverride allows the implementation of an auxiliary ASN.1
decoder for a particular value or scenario. It bypasses the
normal decoding operation that would have otherwise been imposed.

This is only intended for advanced corner-cases and most often
need not be used.
*/
type DecodeOverride[T any] func([]byte) (T, error)

/*
EncodeOverride allows the implementation of an auxiliary ASN.1
encoder for a particular value or scenario. It bypasses the
normal encoding operation that would have otherwise been imposed.

This is only intended for advanced corner-cases and most often
need not be used.
*/
type EncodeOverride[T any] func(T) ([]byte, error)

/*
RegisterTextAlias registers a custom alias of any [Primitive]
~string or ~[]byte based types defined within this package, such
as [PrintableString], [BMPString], [UTF8String], et al.

Note this does NOT include [BitString], which has its own dedicated
constructor [RegisterBitStringAlias].
*/
func RegisterTextAlias[T TextLike](
	tag int,
	verify DecodeVerifier,
	decoder DecodeOverride[T],
	encoder EncodeOverride[T],
	spec Constraint[T],
	user ...Constraint[T]) {

	all := append(ConstraintGroup[T]{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &textCodec[T]{tag: tag, cg: all,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
		newWith: func(v any) box {
			return &textCodec[T]{
				val: valueOf[T](v), tag: tag, cg: all,
				decodeVerify: verList,
				decodeHook:   decoder,
				encodeHook:   encoder}
		},
	}

	rt := reflect.TypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}
