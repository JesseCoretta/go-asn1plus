package asn1plus

/*
common.go contains elements, types and functions used by myriad
components throughout this package.
*/

import (
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

/*
official import aliases.
*/
var (
	mkerr      func(string) error                       = errors.New
	itoa       func(int) string                         = strconv.Itoa
	atoi       func(string) (int, error)                = strconv.Atoi
	fmtUint    func(uint64, int) string                 = strconv.FormatUint
	fmtInt     func(int64, int) string                  = strconv.FormatInt
	fmtFloat   func(float64, byte, int, int) string     = strconv.FormatFloat
	puint      func(string, int, int) (uint64, error)   = strconv.ParseUint
	pbool      func(string) (bool, error)               = strconv.ParseBool
	pfloat     func(string, int) (float64, error)       = strconv.ParseFloat
	lc         func(string) string                      = strings.ToLower
	uc         func(string) string                      = strings.ToUpper
	appInt     func([]byte, int64, int) []byte          = strconv.AppendInt
	appUint    func([]byte, uint64, int) []byte         = strconv.AppendUint
	split      func(string, string) []string            = strings.Split
	join       func([]string, string) string            = strings.Join
	hexstr     func([]byte) string                      = hex.EncodeToString
	stridxb    func(string, byte) int                   = strings.IndexByte
	replace    func(string, string, string, int) string = strings.Replace
	replaceAll func(string, string, string) string      = strings.ReplaceAll
	hasPfx     func(string, string) bool                = strings.HasPrefix
	hasSfx     func(string, string) bool                = strings.HasSuffix
	trimPfx    func(string, string) string              = strings.TrimPrefix
	trimL      func(string, string) string              = strings.TrimLeft
	trimS      func(string) string                      = strings.TrimSpace
	trim       func(string, string) string              = strings.Trim
	cntns      func(string, string) bool                = strings.Contains
	streq      func(string, string) bool                = strings.EqualFold
	isCtrl     func(rune) bool                          = unicode.IsControl
	isPrint    func(rune) bool                          = unicode.IsPrint
	streqf     func(string, string) bool                = strings.EqualFold
	strrpt     func(string, int) string                 = strings.Repeat
	utf16Enc   func([]rune) []uint16                    = utf16.Encode
	utf8OK     func(string) bool                        = utf8.ValidString
	newBigInt  func(int64) *big.Int                     = big.NewInt
)

func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := streqf
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch
			funk = streq
		}
	}

	switch tv := r.(type) {
	case string:
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(tv, slice[i])
		}
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			for j := 0; j < len(slice) && !match; j++ {
				match = funk(tv[i], slice[j])
			}
		}
	}

	return
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

/*
asn1Reader is qualified through any type which bears the "read(Packet, TagAndLength) error" method.
*/
type asn1Reader interface {
	read(Packet, TLV, *Options) error
}

func newStrBuilder() strings.Builder { return strings.Builder{} }

func bool2str(b bool) (s string) {
	if s = `false`; b {
		s = `true`
	}
	return
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
		ptr = reflect.New(rv.Type())
		ptr.Elem().Set(rv)
	}
	return
}

func getTagMethod(x any) (func() int, bool) {
	v := reflect.ValueOf(x)
	method := v.MethodByName("Tag")
	if !method.IsValid() {
		// Might be a SET or SEQUENCE.
		if v.Kind() == reflect.Struct {
			return func() int { return TagSequence }, true
		} else if v.Kind() == reflect.Slice {
			return func() int { return TagSet }, true
		}
		return nil, false
	}

	mType := method.Type()
	if mType.NumIn() != 0 || mType.NumOut() != 1 {
		return nil, false
	}

	tagType := reflect.TypeOf(int(0))
	if !mType.Out(0).AssignableTo(tagType) {
		return nil, false
	}

	tagFunc := func() int {
		results := method.Call(nil)
		return results[0].Interface().(int)
	}

	return tagFunc, true
}

func stringBytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return unsafe.Slice((*byte)(unsafe.Pointer(sh.Data)), sh.Len)
}

func effectiveTag(baseTag, baseClass int, o *Options) (int, int) {
	// 0. Highest priority: CHOICE helper supplying an explicit tag.
	if o.choiceTag != nil {
		baseTag = *o.choiceTag
	}

	// case1: Ignore a *pure* zero-value Options{} (Tag==0 && Class==0).
	if o.Tag() == 0 && o.Class() == 0 {
		return baseTag, baseClass
	}

	// case2: Overlay that includes a TAG (implicit / explicit, incl. tag==0).
	if o.Tag() >= 0 {
		baseTag = o.Tag()   // always replace the tag
		if o.Class() >= 0 { // copy class *IF* caller supplied one
			baseClass = o.Class()
		}
		return baseTag, baseClass
	}

	// case3: Class-only overlay is legal *only* when
	// the primitive's class is still unset (<0).
	if o.HasClass() && baseClass > -1 {
		baseClass = o.Class()
	}
	return baseTag, baseClass
}
