package asn1plus

/*
er.go contains all EncodingRule abstraction elements, including
rule-tailored Packet constructors and runtime Options envelopes.
*/

/*
EncodingRule describes the particular ASN.1 encoding rule of a
[Packet] qualifier type.
*/
type EncodingRule int

const (
	testEncodingRule EncodingRule = iota - 1
	invalidEncodingRule
	BER
	CER
	DER
)

// for unit tests
var encodingRules []EncodingRule = []EncodingRule{BER, CER, DER}

/*
allowsIndefinite returns a Boolean value indicative of whether the
receiver instance allows indefinite lengths.
*/
func (r EncodingRule) allowsIndefinite() (ok bool) {
	switch r {
	case BER, CER:
		ok = true
	}

	return
}

/*
In returns a Boolean instance indicative of r being present within e.
*/
func (r EncodingRule) In(e ...EncodingRule) (is bool) {
	for i := 0; i < len(e) && !is; i++ {
		is = r == e[i]
	}

	return
}

/*
Extends returns a Boolean instance indicative of r extending from e.
*/
func (r EncodingRule) Extends(e EncodingRule) (is bool) {
	switch r {
	case BER:
		is = (e == CER || e == DER)
	}

	return
}

/*
New returns a qualifying instance of [Packet] based on the receiver value.

The variadic data input value(s) are assumed to be previously encoded bytes
appropriate for the receiver in use. If provided, the offset will be set to
the final byte. If none are provided, an empty (but initialized) [Packet]
is returned as-is.
*/
func (r EncodingRule) New(src ...byte) Packet {
	var pkt Packet
	switch r {
	case BER:
		b := berPktPool.Get().(*BERPacket)

		if cap(b.data) < len(src) {
			bufPtr := bufPool.Get().(*[]byte)
			if cap(*bufPtr) < len(src) {
				*bufPtr = make([]byte, 0, roundup(len(src)))
			}
			b.data = *bufPtr
		}

		b.data = append(b.data[:0], src...)
		pkt = b

	case CER:
		b := cerPktPool.Get().(*CERPacket)

		if cap(b.data) < len(src) {
			bufPtr := bufPool.Get().(*[]byte)
			if cap(*bufPtr) < len(src) {
				*bufPtr = make([]byte, 0, roundup(len(src)))
			}
			b.data = *bufPtr
		}

		b.data = append(b.data[:0], src...)
		pkt = b

	case DER:
		d := derPktPool.Get().(*DERPacket)
		if cap(d.data) < len(src) {
			bufPtr := bufPool.Get().(*[]byte)
			if cap(*bufPtr) < len(src) {
				*bufPtr = make([]byte, 0, roundup(len(src)))
			}
			d.data = *bufPtr
		}
		d.data = append(d.data[:0], src...)
		pkt = d

	default:
		pkt = invalidPacket{}
	}

	pkt.SetOffset(-1)
	return pkt
}

func roundup(n int) int { // tiny power-of-two grow helper
	for n&(n-1) != 0 {
		n &= n - 1
	}
	return n << 1
}

func (r EncodingRule) newTLV(class, tag, length int, compound bool, value ...byte) (tlv TLV) {
	if TagSequence <= tag && tag <= TagSet {
		compound = true
	}

	switch r {
	case BER, CER, DER:
		tlv = TLV{typ: r, Class: class, Tag: tag, Length: length, Compound: compound, Value: append([]byte{}, value...)}
	}

	return
}

type EncodingOption func(*encodingConfig)

type encodingConfig struct {
	rule EncodingRule
	opts *Options
}

/*
With encapsulates instances of [EncodingRule] and [Options] into a single payload for
submission to [Marshal] and [Unmarshal]. This function is intended to be executed
in-line as a variadic input value to [Marshal] and [Unmarshal]

It is unnecessary -- but harmless -- to include an [EncodingRule] when submitting to
[Unmarshal], as the input [Packet] instance knows what [EncodingRule] it implements.
*/
func With(args ...any) EncodingOption {
	var rule EncodingRule = invalidEncodingRule
	var opts *Options

	for i := 0; i < len(args); i++ {
		switch tv := args[i].(type) {
		case EncodingRule:
			rule = tv
		case Options:
			opts = &tv
		case *Options:
			opts = tv
		}
	}

	return func(cfg *encodingConfig) {
		cfg.rule = rule
		cfg.opts = opts
	}
}

/*
Deprecated: WithEncoding returns an option to set the encoding rule. This function is intended to
be executed in-line as a varadic input value to [Marshal].

Use [With] instead.
*/
func WithEncoding(rule EncodingRule) EncodingOption {
	return func(cfg *encodingConfig) { cfg.rule = rule }
}

/*
Deprecated: WithOptions returns an option to set the encoding parameters. This function is intended
to be executed in-line as a varadic input value to [Marshal] and [Unmarshal].

Use [With] instead.
*/
func WithOptions(opts Options) EncodingOption { return func(cfg *encodingConfig) { cfg.opts = &opts } }

/*
String returns the string representation of the receiver instance.
*/
func (r EncodingRule) String() string {
	var s string = `invalid`
	switch r {
	case BER:
		s = `BER`
	case CER:
		s = `CER`
	case DER:
		s = `DER`
	}

	return s
}

/*
OID returns the associated encoding rule [ObjectIdentifier] for the
receiver instance.
*/
func (r EncodingRule) OID() ObjectIdentifier {
	var oid ObjectIdentifier
	switch r {
	case BER:
		oid = berOID
	case CER:
		oid = cerOID
	case DER:
		oid = derOID
	}

	return oid
}
