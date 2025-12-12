package asn1plus

/*
enum.go contains all types and methods pertaining to the ASN.1
ENUMERATED type.
*/

import "reflect"

/*
EnumeratedConstraintPhase declares the appropriate phase
for the constraining of values during codec operations.

See the [CodecConstraintNone], [CodecConstraintEncoding],
[CodecConstraintDecoding] and [CodecConstraintBoth] constants
for possible settings.
*/
var EnumeratedConstraintPhase = CodecConstraintDecoding

/*
Enumerated implements the ASN.1 ENUMERATED type (tag 10).
*/
type Enumerated int

/*
Tag returns the integer constant [TagEnum].
*/
func (_ Enumerated) Tag() int { return TagEnum }

/*
Enumerated returns the string representation of the receiver instance.
*/
func (r Enumerated) String() string { return itoa(int(r)) }

/*
IsPrimitive returns true, indicating the receiver is considered an
ASN.1 primitive type. This method serves as a marker to differentiate
qualified instances from other interfaces of a similar design.
*/
func (_ Enumerated) IsPrimitive() bool { return true }

/*
NewEnumerated returns an instance of [Enumerated] alongside an error
following an attempt to marshal x.

See also [MustNewEnumerated].
*/
func NewEnumerated(x any, constraints ...Constraint) (enum Enumerated, err error) {
	var e int
	switch tv := x.(type) {
	case int:
		e = tv
	case Enumerated:
		e = int(tv)
	default:
		err = errorBadTypeForConstructor("ENUMERATED", x)
	}

	if len(constraints) > 0 && err == nil {
		err = ConstraintGroup(constraints).Constrain(Enumerated(e))
	}

	if err == nil {
		enum = Enumerated(e)
	}

	return
}

/*
MustNewEnumerated returns an instance of [Enumerated] and panics if
[NewEnumerated] returned an error during processing of x.
*/
func MustNewEnumerated(x any, constraints ...Constraint) Enumerated {
	b, err := NewEnumerated(x, constraints...)
	if err != nil {
		panic(err)
	}
	return b
}

type enumeratedCodec[T ~int] struct {
	val  T
	base *integerCodec[Integer]
}

/* box-interface plumbing */
func (c *enumeratedCodec[T]) Tag() int          { return c.base.tag }
func (c *enumeratedCodec[T]) IsPrimitive() bool { return true }
func (c *enumeratedCodec[T]) getVal() any       { return c.val }
func (c *enumeratedCodec[T]) setVal(v any)      { c.val = valueOf[T](v) }
func (c *enumeratedCodec[T]) String() string    { return "enumeratedCodec" }

func (c *enumeratedCodec[T]) write(pkt PDU, o *Options) (int, error) {
	c.base.val = Integer{native: int64(c.val)}
	return c.base.write(pkt, o)
}

func (c *enumeratedCodec[T]) read(pkt PDU, tlv TLV, o *Options) (err error) {
	if err = c.base.read(pkt, tlv, o); err == nil {
		c.val = T(c.base.val.native)
	}
	return
}

func RegisterEnumeratedAlias[T ~int](
	tag int,
	cphase int,
	verify DecodeVerifier,
	encoder EncodeOverride[T],
	decoder DecodeOverride[T],
	spec Constraint,
	user ...Constraint) {

	allCS := ConstraintGroup{}

	var verList []DecodeVerifier
	if verify != nil {
		verList = []DecodeVerifier{verify}
	}

	if spec != nil {
		allCS = append(allCS, func(i any) error {
			return spec(i)
		})
	}
	for _, u := range user {
		fn := u
		allCS = append(allCS, func(i any) error {
			return fn(i)
		})
	}

	var eHook EncodeOverride[Integer]
	if encoder != nil {
		eHook = func(i Integer) ([]byte, error) {
			return encoder(T(i.native))
		}
	}

	var dHook DecodeOverride[Integer]
	if decoder != nil {
		dHook = func(b []byte) (eVal Integer, err error) {
			var tmp T
			if tmp, err = decoder(b); err == nil {
				eVal = Integer{native: int64(tmp)}
			}
			return
		}
	}

	base := &integerCodec[Integer]{
		tag:          tag,
		cphase:       cphase,
		cg:           allCS,
		decodeVerify: verList,
		encodeHook:   eHook,
		decodeHook:   dHook,
	}

	f := factories{
		newEmpty: func() box { return &enumeratedCodec[T]{base: base} },
		newWith: func(v any) box {
			return &enumeratedCodec[T]{val: valueOf[T](v), base: base}
		},
	}

	rt := refTypeOf((*T)(nil)).Elem()
	registerType(rt, f)
	registerType(reflect.PointerTo(rt), f)
}

func init() {
	RegisterEnumeratedAlias[Enumerated](TagEnum,
		EnumeratedConstraintPhase,
		nil, nil, nil, nil)
}
