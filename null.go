package asn1plus

/*
null.go contains all types and methods pertaining to the ASN.1
NULL type.
*/

import "reflect"

/*
Null implements the ASN.1 NULL type (tag 5).

There is no constructor for instances of this type.
*/
type Null struct{}

/*
NullConstraintPhase declares the appropriate phase for the
constraining of values during codec operations. See the
[CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var NullConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagNull].
*/
func (_ Null) Tag() int { return TagNull }

/*
Len always returns zero (0).
*/
func (_ Null) Len() int { return 0 }

/*
Null returns the string representation of the receiver instance,
which is a single Null Terminating Byte Sequence ("NTBS").
*/
func (_ Null) String() string { return string(rune(0)) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (_ Null) IsPrimitive() bool { return true }

type nullCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup[T]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *nullCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdNullWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdNullWrite[T any](c *nullCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		}

		if err == nil {
			tag, cls := effectiveHeader(c.tag, 0, o)
			start := pkt.Offset()
			err = writeTLV(pkt, pkt.Type().newTLV(cls, tag, len(wire), false), o)
			if err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *nullCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdNullRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}
	return
}

func bcdNullRead[T any](c *nullCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.tag, pkt, tlv, o)
	if err == nil {
		decodeVerify := func() (err error) {
			for i := 0; i < len(c.decodeVerify) && err == nil; i++ {
				err = c.decodeVerify[i](wire)
			}

			return
		}

		if err = decodeVerify(); err == nil {
			var out T
			if c.decodeHook != nil {
				out, err = c.decodeHook(wire)
			} else {
				err = errorNullLengthNonZero(tlv.Length)
			}

			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = out
					pkt.AddOffset(tlv.Length)
				}
			}
		}
	}

	return err
}

func (c *nullCodec[T]) Tag() int          { return c.tag }
func (c *nullCodec[T]) IsPrimitive() bool { return true }
func (c *nullCodec[T]) String() string    { return "nullCodec" }
func (c *nullCodec[T]) getVal() any       { return c.val }
func (c *nullCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func RegisterNullAlias[T any](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint[T],
	user ...Constraint[T],
) {
	all := append(ConstraintGroup[T]{spec}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &nullCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
		newWith: func(v any) box {
			return &nullCodec[T]{val: valueOf[T](v),
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterNullAlias[Null](TagNull,
		NullConstraintPhase,
		nil, nil, nil, nil)
}
