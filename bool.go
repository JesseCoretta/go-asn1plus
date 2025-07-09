package asn1plus

/*
bool.go contains all types and methods pertaining to the ASN.1
BOOLEAN type.
*/

import (
	"reflect"
	"unsafe"
)

/*
Boolean implements the ASN.1 BOOLEAN type.
*/
type Boolean bool

/*
BooleanConstraintPhase declares the appropriate phase for
the constraining of values during codec operations. See the
[CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var BooleanConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant one (1) for [TagBoolean].
*/
func (r Boolean) Tag() int { return TagBoolean }

/*
Byte returns the verisimilitude of the receiver instance expressed
as a byte: 0x0 for false, 0xFF for true.
*/
func (r Boolean) Byte() byte {
	var b byte
	if bool(r) {
		b = 0xFF
	}

	return b
}

/*
String returns the string representation of the receiver instance.
*/
func (r Boolean) String() string { return bool2str(bool(r)) }

/*
Bool returns the receiver instance cast as a native Go bool.
*/
func (r Boolean) Bool() bool { return bool(r) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (r Boolean) IsPrimitive() bool { return true }

/*
NewBoolean returns an instance of [Boolean] alongside an error following
an attempt to marshal x.
*/
func NewBoolean(x any, constraints ...Constraint[Boolean]) (b Boolean, err error) {
	switch tv := x.(type) {
	case Boolean:
		b = tv
	case Primitive:
		b, err = NewBoolean(tv.String())
	case bool:
		b = Boolean(tv)
	case *bool:
		if tv != nil {
			b = Boolean(*tv)
		}
	case string:
		var _b bool
		_b, err = pbool(tv)
		b = Boolean(_b)
	case int:
		b = Boolean(tv == 1)
	case byte:
		b = Boolean(tv == 0xFF)
	default:
		err = errorBadTypeForConstructor("BOOLEAN", x)
	}

	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[Boolean] = constraints
		err = group.Constrain(Boolean(b == true))
	}

	return b, err
}

type booleanCodec[T any] struct {
	val    T
	tag    int
	cphase int
	cg     ConstraintGroup[T]

	decodeVerify []DecodeVerifier
	encodeHook   EncodeOverride[T]
	decodeHook   DecodeOverride[T]
}

func (c *booleanCodec[T]) Tag() int          { return c.tag }
func (c *booleanCodec[T]) IsPrimitive() bool { return true }
func (c *booleanCodec[T]) getVal() any       { return c.val }
func (c *booleanCodec[T]) String() string    { return "booleanCodec" }
func (c *booleanCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }

func toBoolean[T any](v T) Boolean   { return *(*Boolean)(unsafe.Pointer(&v)) }
func fromBoolean[T any](i Boolean) T { return *(*T)(unsafe.Pointer(&i)) }

func (c *booleanCodec[T]) write(pkt PDU, o *Options) (n int, err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		n, err = bcdBooleanWrite(c, pkt, o)
	default:
		err = errorRuleNotImplemented
	}

	return
}

func bcdBooleanWrite[T any](c *booleanCodec[T], pkt PDU, o *Options) (off int, err error) {
	o = deferImplicit(o)

	cc := c.cg.phase(c.cphase, CodecConstraintEncoding)
	if err = cc(c.val); err == nil {
		var wire []byte = []byte{0x00} // assume FALSE
		var err error
		if c.encodeHook != nil {
			wire, err = c.encodeHook(c.val)
		} else {
			if toBoolean(c.val).Bool() {
				wire = []byte{0xFF}
			}
		}

		if err == nil {
			tag, cls := effectiveTag(c.Tag(), 0, o)
			start := pkt.Offset()

			tlv := pkt.Type().newTLV(cls, tag, 1, false, wire[0])
			if err = writeTLV(pkt, tlv, o); err == nil {
				off = pkt.Offset() - start
			}
		}
	}

	return
}

func (c *booleanCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	switch pkt.Type() {
	case BER, CER, DER:
		err = bcdBooleanRead(c, pkt, tlv, o)
	default:
		err = errorRuleNotImplemented
	}

	return
}

func bcdBooleanRead[T any](c *booleanCodec[T], pkt PDU, tlv TLV, o *Options) error {
	o = deferImplicit(o)

	wire, err := primitiveCheckRead(c.Tag(), pkt, tlv, o)
	if err == nil {
		if len(wire) != 1 {
			return mkerr("BOOLEAN: content length ≠ 1")
		}

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
				out = fromBoolean[T](Boolean(wire[0] != 0))
			}

			if err == nil {
				cc := c.cg.phase(c.cphase, CodecConstraintDecoding)
				if err = cc(out); err == nil {
					c.val = out
					pkt.SetOffset(pkt.Offset() + 1)
				}
			}
		}
	}

	return err
}

func RegisterBooleanAlias[T any](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint[T],
	user ...Constraint[T],
) {
	all := append(ConstraintGroup[T]{}, user...)

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	f := factories{
		newEmpty: func() box {
			return &booleanCodec[T]{
				tag: tag, cg: all,
				cphase:       cphase,
				decodeVerify: verList,
				encodeHook:   encoder,
				decodeHook:   decoder}
		},
		newWith: func(v any) box {
			return &booleanCodec[T]{val: valueOf[T](v),
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
	RegisterBooleanAlias[Boolean](TagBoolean,
		BooleanConstraintPhase,
		nil, nil, nil, nil)
}
