package asn1plus

/*
ns.go contains all types and methods pertaining to the ASN.1
NUMERIC STRING type.
*/

import "reflect"

/*
NumericString implements the ASN.1 NUMERICSTRING type per [ITU-T Rec. X.680]:

	Digits     0, 1, ... 9
	Space

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type NumericString string

/*
Tag returns the integer constant [TagNumericString].
*/
func (r NumericString) Tag() int { return TagNumericString }

/*
IsPrimitive returns true, indicating the receiver is a known
ASN.1 primitive.
*/
func (r NumericString) IsPrimitive() bool { return true }

/*
Len returns the integer length of the receiver instance.
*/
func (r NumericString) Len() int { return len(r) }

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NumericString) IsZero() bool { return len(r) == 0 }

/*
NewNumericString returns an instance of [NumericString] alongside
an error following an attempt to marshal x.
*/
func NewNumericString(x any, constraints ...Constraint[NumericString]) (ns NumericString, err error) {
	var raw string
	if raw, err = convertToNumericString(x); err == nil {
		// Validate that raw contains only digits and space.

		_ns := NumericString(raw)
		err = NumericSpec(_ns)
		if len(constraints) > 0 && err == nil {
			var group ConstraintGroup[NumericString] = constraints
			err = group.Validate(_ns)
		}

		if err == nil {
			ns = _ns
		}
	}
	return
}

/*
NumericSpec implements the formal [Constraint] specification for [NumericString].
*/
var NumericSpec Constraint[NumericString]

func convertToNumericString(x any) (str string, err error) {
	// Do an explicit check for string first.
	if s, ok := x.(string); ok {
		if len(s) == 0 {
			err = mkerr("ASN.1 NUMERICSTRING is zero")
			return
		}
		str = s
		return
	} else if ns, ok := x.(NumericString); ok {
		if len(ns) == 0 {
			err = mkerr("ASN.1 NUMERICSTRING is zero")
			return
		}
		str = ns.String()
		return
	}

	// Otherwise, use reflection on numeric types.
	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := v.Int()
		if i < 0 {
			err = mkerr("Illegal sign (-) for ASN.1 NUMERICSTRING")
		} else {
			str = fmtInt(i, 10)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		str = fmtUint(v.Uint(), 10)
	default:
		err = mkerr("Invalid type for ASN.1 NUMERICSTRING")
	}

	return
}

func init() {
	RegisterTextAlias[NumericString](TagNumericString, nil, nil, nil, NumericSpec)

	NumericSpec = func(o NumericString) (err error) {
		for _, c := range []rune(o.String()) {
			if !(c == ' ' || (c >= '0' && c <= '9')) {
				err = mkerrf("Illegal character for ASN.1 NUMERICSTRING: ", string(c))
				break
			}
		}

		return
	}
}
