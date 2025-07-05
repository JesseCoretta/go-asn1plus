package asn1plus

/*
er.go contains all EncodingRule abstraction elements, including
rule-tailored PDU constructors and runtime Options envelopes.
*/

/*
EncodingRule describes the particular ASN.1 encoding rule of a
[PDU] qualifier type.
*/
type EncodingRule int

/*
DefaultEncoding declares the default [EncodingRule] to be used,
unless otherwise instructed, for all [Marshal] operations. This
can be changed by the end user (e.g.: use [DER] as default).

If an unimplemented, disabled or otherwise unsupported [EncodingRule]
is declared here, the package will panic.
*/
var DefaultEncoding EncodingRule = BER

const (
	testEncodingRule EncodingRule = iota - 1
	invalidEncodingRule
)

/*
[EncodingRule] constants outline all of the supported
(but not necessarily loaded) ASN.1 encoding rules in
this package.
*/
const (
	BER EncodingRule = 1 << iota // 1
	CER                          // 2
	DER                          // 4
)

/*
activeEncodingRules represents an EncodingRule bitmask,
detailing which rules have support compiled for them.
*/
var activeEncodingRules = BER

/*
for unit tests, enforcement and officiation of all supported
encoding rules within this package.  This is essentially the
"master list" of all possible encoding rules in this package,
but does not reflect which rules are LOADED.
*/
var allEncodingRules []EncodingRule = []EncodingRule{BER, CER, DER}

/*
Enabled returns a Boolean value indicative of whether support for
[EncodingRule] r was enabled with "-tags <rule>" at build/run time.
*/
func (r EncodingRule) Enabled() bool { return activeEncodingRules&r != 0 }

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
New returns a qualifying instance of [PDU] based on the receiver value.

The variadic data input value(s) are assumed to be previously encoded bytes
appropriate for the receiver in use. If provided, the offset will be set to
the final byte. If none are provided, an empty (but initialized) [PDU]
is returned as-is.
*/
func (r EncodingRule) New(src ...byte) PDU {
	var pkt PDU = invalidPacket{}

	if r.Enabled() {
		pkt = pDUConstructors[r](src...)
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
in-line as a variadic input value to [Marshal] and [Unmarshal].

It is unnecessary -- but harmless -- to include an [EncodingRule] when submitting to
[Unmarshal], as the input [PDU] instance knows what [EncodingRule] it implements.
*/
func With(args ...any) EncodingOption {
	var rule EncodingRule = invalidEncodingRule
	var opts *Options

	for i := 0; i < len(args); i++ {
		switch tv := args[i].(type) {
		case EncodingRule:
			if tv.Enabled() {
				rule = tv
			}
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

/*
prebuilt list of enabled encoding rules for use
in test/op iteration.
*/
var encodingRules []EncodingRule

func init() {
	for _, r := range allEncodingRules {
		if r.Enabled() {
			encodingRules = append(encodingRules, r)
		}
	}

	if len(encodingRules) == 0 {
		panic(errorNoEncodingRules)
	} else if !DefaultEncoding.Enabled() {
		panic(errorRuleNotImplemented)
	}
}
