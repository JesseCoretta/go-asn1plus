package asn1plus

/*
oct.go contains all types and methods pertaining to the ASN.1
OCTET STRING type.
*/

/*
OctetString returns an instance of [OctetString] alongside an error
following an attempt to marshal x.
*/
func NewOctetString(x any, constraints ...Constraint[OctetString]) (oct OctetString, err error) {
	var str string

	switch tv := x.(type) {
	case []byte:
		str = string(tv)
	case string:
		str = tv
	case OctetString:
		str = tv.String()
	default:
		err = mkerr("Invalid type for ASN.1 OCTET STRING")
		return
	}

	_oct := OctetString(str)
	err = OctetSpec(_oct)
	if len(constraints) > 0 && err == nil {
		var group ConstraintGroup[OctetString] = constraints
		err = group.Validate(_oct)
	}

	if err == nil {
		oct = _oct
	}

	return
}

/*
OctetSpec implements the formal [Constraint] specification for [OctetString].

Note that this specification is automatically executed during construction and
need not be specified manually as a [Constraint] by the end user.
*/
var OctetSpec Constraint[OctetString]

/*
OctetString implements the ASN.1 OCTET STRING type (tag 4).
*/
type OctetString []byte

/*
Tag returns the integer constant [TagOctetString].
*/
func (r OctetString) Tag() int { return TagOctetString }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *OctetString) IsZero() bool { return r == nil }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r OctetString) IsPrimitive() bool { return true }

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string { return string(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r OctetString) Len() int {
	var l int
	if &r != nil {
		l = len(r)
	}
	return l
}

func init() {
	RegisterTextAlias[OctetString](TagOctetString, nil, nil, nil, OctetSpec)
	OctetSpec = func(o OctetString) (err error) {
		for _, r := range []rune(o.String()) {
			if r > 0x00FF {
				err = mkerrf("Invalid character '", string(r), "' (>0x00FF) in OCTET STRING")
				break
			}
		}
		return
	}
}
