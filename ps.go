package asn1plus

/*
ps.go contains all types and methods pertaining to the ASN.1
PRINTABLE STRING type.
*/

/*
PrintableString implements [§ 41.4 of ITU-T Rec. X.680] (tag 19):

	Latin capital letters   A, B, ... Z
	Latin small letters     a, b, ... z
	Digits                  0, 1, ... 9
	SPACE
	APOSTROPHE              '
	LEFT PARENTHESIS        (
	RIGHT PARENTHESIS       )
	PLUS SIGN               +
	COMMA                   ,
	HYPHEN-MINUS            -
	FULL STOP               .
	SOLIDUS                 /
	COLON                   :
	EQUALS SIGN             =
	QUESTION MARK           ?

[§ 41.4 of ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type PrintableString string

/*
PrintableStringConstraintPhase declares the appropriate phase
for the constraining of values during codec operations. See
the [CodecConstraintEncoding], [CodecConstraintDecoding] and
[CodecConstraintBoth] constants for possible settings.
*/
var PrintableStringConstraintPhase = CodecConstraintDecoding

/*
Tag returns the integer constant [TagPrintableString].
*/
func (r PrintableString) Tag() int { return TagPrintableString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r PrintableString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r PrintableString) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r PrintableString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PrintableString) IsZero() bool { return len(r) == 0 }

/*
NewPrintableString returns an instance of [PrintableString] alongside
an error following an attempt to marshal x.
*/
func NewPrintableString(x any, constraints ...Constraint[PrintableString]) (ps PrintableString, err error) {
	var raw string

	switch tv := x.(type) {
	case Primitive:
		raw = tv.String()
	case string:
		if len(tv) == 0 {
			err = mkerr("Printable String is zero length")
			return
		}
		raw = tv
	case []byte:
		raw = string(tv)
	default:
		err = errorBadTypeForConstructor("PRINTABLE STRING", x)
		return
	}

	_ps := PrintableString(raw)
	err = PrintableSpec(_ps)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[PrintableString] = constraints
		err = group.Constrain(PrintableString(raw))
	}

	if err == nil {
		ps = _ps
	}

	return
}

/*
PrintableSpec implements the formal [Constraint] specification for [PrintableString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var PrintableSpec Constraint[PrintableString]

var printableStringBitmap [65536 / 64]uint64 // one cache-line per 64 runes

func init() {
	RegisterTextAlias[PrintableString](TagPrintableString,
		PrintableStringConstraintPhase, nil, nil, nil, PrintableSpec)

	PrintableSpec = func(o PrintableString) (err error) {
		for _, r := range []rune(o.String()) {
			if r < 0 || r > 0xFFFF {
				err = mkerrf("Invalid character '", string(r), "' (>0xFFFF) in PRINTABLE STRING")
				break
			}
			word := r >> 6
			bit := r & 63
			if (printableStringBitmap[word]>>bit)&1 == 0 {
				err = mkerrf("Invalid character '", string(r), "' (", itoa(int(r)), ") in PRINTABLE STRING")
				break
			}
		}

		return
	}

	set := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			printableStringBitmap[r>>6] |= 1 << (r & 63)
		}
	}
	set(0x0020, 0x0020)
	set(0x0027, 0x0029)
	set(0x002B, 0x002F)
	set(0x003A, 0x003A)
	set(0x003F, 0x003F)
	set(0x0030, 0x0039)
	set(0x0041, 0x005A)
	set(0x0061, 0x007A)
}
