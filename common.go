package asn1plus

/*
common.go contains elements, types and functions used by myriad
components throughout this package.
*/

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

/*
official import aliases.
*/
var (
	bcmp       func([]byte, []byte) int                            = bytes.Compare
	bidx       func([]byte, []byte) int                            = bytes.Index
	btseq      func([]byte, []byte) bool                           = bytes.Equal
	itoa       func(int) string                                    = strconv.Itoa
	atoi       func(string) (int, error)                           = strconv.Atoi
	fmtUint    func(uint64, int) string                            = strconv.FormatUint
	fmtInt     func(int64, int) string                             = strconv.FormatInt
	fmtFloat   func(float64, byte, int, int) string                = strconv.FormatFloat
	puint      func(string, int, int) (uint64, error)              = strconv.ParseUint
	pbool      func(string) (bool, error)                          = strconv.ParseBool
	pfloat     func(string, int) (float64, error)                  = strconv.ParseFloat
	appInt     func([]byte, int64, int) []byte                     = strconv.AppendInt
	appUint    func([]byte, uint64, int) []byte                    = strconv.AppendUint
	lc         func(string) string                                 = strings.ToLower
	uc         func(string) string                                 = strings.ToUpper
	split      func(string, string) []string                       = strings.Split
	join       func([]string, string) string                       = strings.Join
	idxr       func(string, rune) int                              = strings.IndexRune
	lidx       func(string, string) int                            = strings.LastIndex
	stridxb    func(string, byte) int                              = strings.IndexByte
	replace    func(string, string, string, int) string            = strings.Replace
	replaceAll func(string, string, string) string                 = strings.ReplaceAll
	hasPfx     func(string, string) bool                           = strings.HasPrefix
	hasSfx     func(string, string) bool                           = strings.HasSuffix
	trimPfx    func(string, string) string                         = strings.TrimPrefix
	trimL      func(string, string) string                         = strings.TrimLeft
	trimR      func(string, string) string                         = strings.TrimRight
	trimS      func(string) string                                 = strings.TrimSpace
	trim       func(string, string) string                         = strings.Trim
	cntns      func(string, string) bool                           = strings.Contains
	countstr   func(string, string) int                            = strings.Count
	streq      func(string, string) bool                           = strings.EqualFold
	streqf     func(string, string) bool                           = strings.EqualFold
	strrpt     func(string, int) string                            = strings.Repeat
	strfld     func(string) []string                               = strings.Fields
	isCtrl     func(rune) bool                                     = unicode.IsControl
	isPrint    func(rune) bool                                     = unicode.IsPrint
	ilc        func(rune) bool                                     = unicode.IsLower
	iuc        func(rune) bool                                     = unicode.IsUpper
	isDigit    func(rune) bool                                     = unicode.IsDigit
	utf16Enc   func([]rune) []uint16                               = utf16.Encode
	utf8OK     func(string) bool                                   = utf8.ValidString
	hexstr     func([]byte) string                                 = hex.EncodeToString
	newBigInt  func(int64) *big.Int                                = big.NewInt
	refTypeOf  func(any) reflect.Type                              = reflect.TypeOf
	refValueOf func(any) reflect.Value                             = reflect.ValueOf
	refNew     func(reflect.Type) reflect.Value                    = reflect.New
	refMkSl    func(reflect.Type, int, int) reflect.Value          = reflect.MakeSlice
	deepEq     func(any, any) bool                                 = reflect.DeepEqual
	refAppend  func(reflect.Value, ...reflect.Value) reflect.Value = reflect.Append
	refPtrTo   func(reflect.Type) reflect.Type                     = reflect.PtrTo
)

/*
Lengthy is qualified through any type which bears the "Len() int" method.
*/
type Lengthy interface {
	Len() int
}

/*
sizeOfInt returns the byte size of i based on its magnitude.
*/
func sizeOfInt(i int) int {
	bn := func(n int) int {
		if n <= 0 {
			return 1
		}
		return int(math.Ceil(math.Log2(float64(n + 1))))
	}

	return (bn(i) + 7) / 8
}

func ptrInt(x int) *int { return &x }

func newStrBuilder() strings.Builder { return strings.Builder{} }

func bool2str(b bool) (s string) {
	if s = `false`; b {
		s = `true`
	}
	return
}

func valueOf[T any](v any) T {
	switch t := v.(type) {
	case T:
		return t
	case *T:
		return *t
	default:
		panic("asn1plus: factory received incompatible type")
	}
}

func ptrIsNil(v reflect.Value) bool {
	return v.Kind() == reflect.Ptr && v.IsNil()
}

func derefTypePtr(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

func derefValuePtr(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	return v
}

/*
canAssign returns an error following an attempt to verify whether src
can be written into dest. This function is called exclusively by the
refSetValue function.

If dest is addressable in some manner, it returns nil. Otherwise it
returns a non-nil error describing the mismatch.
*/
func canAssign(dest, src reflect.Value) (err error) {
	if !dest.IsValid() {
		err = generalErrorf("destination is invalid")
	} else if !dest.CanSet() {
		err = generalErrorf("destination of type ", dest.Type(), " is not settable")
	} else {
		dType := dest.Type()
		sType := src.Type()
		if !(sType.AssignableTo(dType) || sType.ConvertibleTo(dType)) {
			// neither direct assignment nor conversion
			// seem to apply here ...
			err = generalErrorf("cannot assign value of type ", sType,
				" to destination of type ", dType)
		}
	}

	return
}

/*
refSetValue returns an error following an attempt to write src into dest
*/
func refSetValue(dest, src reflect.Value) (err error) {
	if err := canAssign(dest, src); err == nil {
		if src.Type().AssignableTo(dest.Type()) {
			dest.Set(src)
		} else {
			dest.Set(src.Convert(dest.Type()))
		}
	}
	return
}

func unwrapInterface(val reflect.Value) reflect.Value {
	// Loop until val is neither an interface nor a pointer.
	for (val.Kind() == reflect.Interface || val.Kind() == reflect.Ptr) && !val.IsNil() {
		val = val.Elem()
	}
	return val
}

func isBool(x string) bool {
	_, err := pbool(x)
	return err == nil
}

func isNumber(x string) bool {
	x = trimL(x, `-`)
	if len(x) == 0 {
		return false
	}

	for _, c := range x {
		if !('0' <= rune(c) && rune(c) <= '9') {
			return false
		}
	}

	if len(x) > 1 {
		if x[0] == '0' {
			return false // no octal numbers
		}
	}

	return true
}

func validClass(class any) bool {
	var c int = -1
	switch tv := class.(type) {
	case string:
		if num, err := atoi(tv); err == nil {
			c = num
		}
	case int:
		c = tv
	}
	return ClassUniversal <= c && c <= ClassPrivate
}

func toPtr(rv reflect.Value) (ptr reflect.Value) {
	// Unwrap interface values if necessary.
	if rv.Kind() == reflect.Interface && !rv.IsNil() {
		rv = rv.Elem()
	}
	if rv.Kind() == reflect.Ptr {
		// If already a pointer, use it directly.
		ptr = rv
	} else if rv.CanAddr() {
		// Field is addressable; use its address.
		ptr = rv.Addr()
	} else {
		// Not addressable: allocate a new instance and set its value.
		ptr = refNew(rv.Type())
		ptr.Elem().Set(rv)
	}
	return
}

func getTagMethod(x any) (func() int, bool) {
	v := refValueOf(x)
	method := v.MethodByName("Tag")
	if !method.IsValid() {
		// Might be a SET or SEQUENCE.
		k := v.Kind()
		if k == reflect.Struct {
			return func() int { return TagSequence }, true
		} else if k == reflect.Slice {
			return func() int { return TagSet }, true
		}
		return nil, false
	}

	mType := method.Type()
	if mType.NumIn() != 0 || mType.NumOut() != 1 {
		return nil, false
	}

	tagType := refTypeOf(0)
	if !mType.Out(0).AssignableTo(tagType) {
		return nil, false
	}

	tagFunc := func() int {
		results := method.Call(nil)
		return results[0].Interface().(int)
	}

	return tagFunc, true
}

func effectiveHeader(baseTag, baseClass int, o *Options) (int, int) {
	if o == nil {
		return baseTag, baseClass
	}

	// Ignore a *pure* zero-value Options{} (Tag==0 && Class==0).
	if o.Tag() == 0 && o.Class() == 0 {
		return baseTag, baseClass
	}

	// Overlay that includes a TAG (implicit / explicit, incl. tag==0).
	if o.Tag() >= 0 {
		baseTag = o.Tag()   // always replace the tag
		if o.Class() >= 0 { // copy class *IF* caller supplied one
			baseClass = o.Class()
		}
		return baseTag, baseClass
	}

	// Class-only overlay is legal *only* when
	// the primitive's class is still unset (<0).
	if o.HasClass() && baseClass > -1 {
		baseClass = o.Class()
	}
	return baseTag, baseClass
}

/*
condense any consecutive combinations of SPACE, HORIZONTAL
TAB or NEW LINE with a single SPACE rune.
*/
func condenseWHSP(b string) string {
	b = trimS(b)
	a := newStrBuilder()

	var last bool
	for i := 0; i < len(b); i++ {
		c := rune(b[i])
		switch c {
		case ' ', '\n', '\t':
			if !last {
				last = true
				a.WriteRune(' ')
			}
		default:
			if last {
				last = false
			}
			a.WriteRune(c)
		}
	}

	return a.String()
}
