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
	DER
)

// for unit tests
var encodingRules []EncodingRule = []EncodingRule{BER, DER}

/*
New returns a qualifying instance of [Packet] based on the receiver value.

The variadic data input value(s) are assumed to be previously encoded bytes
appropriate for the receiver in use. If provided, the offset will be set to
the final byte. If none are provided, an empty (but initialized) [Packet]
is returned as-is.
*/
func (r EncodingRule) New(data ...byte) Packet {
	var pkt Packet = invalidPacket{}

	switch r {
	case BER:
		b := &BERPacket{}
		b.data = data
		pkt = b

	case DER:
		d := &DERPacket{}
		d.data = data
		pkt = d
	}

	pkt.SetOffset(-1)
	return pkt
}

func (r EncodingRule) newTLV(class, tag, length int, compound bool, value ...byte) (tlv TLV) {
	if TagSequence <= tag && tag <= TagSet {
		compound = true
	}

	switch r {
	case BER, DER:
		tlv = TLV{typ: r, Class: class, Tag: tag, Length: length, Compound: compound, Value: []byte(value)}
	}

	return
}

type EncodingOption func(*encodingConfig)

type encodingConfig struct {
	rule EncodingRule
	opts *Options
}

/*
WithEncoding returns an option to set the encoding rule. This function is intended to
be executed in-line as a varadic input value to [Marshal].

See also [WithOptions].
*/
func WithEncoding(rule EncodingRule) EncodingOption {
	return func(cfg *encodingConfig) {
		cfg.rule = rule
	}
}

/*
WithOptions returns an option to set the encoding parameters. This function is intended to
be executed in-line as a varadic input value to [Marshal] and [Unmarshal].

See also [WithEncoding].
*/
func WithOptions(opts Options) EncodingOption {
	return func(cfg *encodingConfig) {
		cfg.opts = &opts
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r EncodingRule) String() string {
	var s string = `invalid`
	switch r {
	case BER:
		s = `BER`
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
	case DER:
		oid = derOID
	}

	return oid
}
