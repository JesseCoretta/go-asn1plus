package asn1plus

import (
	"reflect"
	"testing"
)

func TestCommon_codecov(_ *testing.T) {
	strs1 := []string{"1", "2", "3"}
	strs2 := []string{"3", "4", "5"}
	strInSlice(strs1, strs2, true)
	sizeOfInt(-1)
	sizeOfInt(3)
	sizeOfInt(33333)
	isNumber("-")
	isNumber("A")
	isNumber("3")
	isNumber("33")
	isNumber("033")
	validClass("9")
	var iface interface{} = struct{ Name string }{}
	toPtr(reflect.ValueOf(iface))
	toPtr(reflect.ValueOf(&iface))

	var oct OctetString = OctetString("yoo")
	var pdv EmbeddedPDV
	getTagMethod(oct)
	getTagMethod(pdv)
	getTagMethod([]any{1, 2, 3})
	getTagMethod(iface)
}

type (
	primitiveAlias int
	plainStruct    struct{ A int }
	sliceAlias     []byte
	badSigIn       struct{}
	badSigOut      struct{}
	good           struct{}
)

func (badSigIn) Tag(_ int) int { return 99 }
func (badSigOut) Tag() string  { return "oops" }
func (good) Tag() int          { return 0x2A }

func TestGetTagMethod_AllBranches(t *testing.T) {
	cases := []struct {
		name  string
		input any
		ok    bool
		exp   int // only relevant when ok==true
	}{
		{
			name:  "struct without Tag() → TagSequence",
			input: plainStruct{},
			ok:    true,
			exp:   TagSequence,
		},
		{
			name:  "slice without Tag() → TagSet",
			input: sliceAlias{0x01, 0x02},
			ok:    true,
			exp:   TagSet,
		},
		{
			name:  "neither struct/slice nor Tag() → nil,false",
			input: primitiveAlias(7),
			ok:    false,
		},
		{
			name:  "Tag method wrong *input* arity → nil,false",
			input: badSigIn{},
			ok:    false,
		},
		{
			name:  "Tag method wrong *output* type → nil,false",
			input: badSigOut{},
			ok:    false,
		},
		{
			name:  "proper Tag() int method",
			input: good{},
			ok:    true,
			exp:   42,
		},
	}

	for _, tc := range cases {
		fn, ok := getTagMethod(tc.input)
		if ok != tc.ok {
			t.Fatalf("%s: expected ok=%v, got %v", tc.name, tc.ok, ok)
		}
		if !ok {
			if fn != nil {
				t.Fatalf("%s: expected nil func when ok==false", tc.name)
			}
			continue
		}

		if fn == nil {
			t.Fatalf("%s: expected non-nil func", tc.name)
		}
		if got := fn(); got != tc.exp {
			t.Fatalf("%s: tag value mismatch – got %d want %d", tc.name, got, tc.exp)
		}
	}
}

func TestToPtr_UnwrapInterfaceBranch(t *testing.T) {
	// Step 1: build a non-nil interface value.
	var iface interface{} = 456

	// Step 2: obtain a reflect.Value that still has Kind()==Interface.
	//         Using Elem() on the address does the trick.
	rv := reflect.ValueOf(&iface).Elem()
	if rv.Kind() != reflect.Interface {
		t.Fatalf("sanity: expected Interface kind, got %v", rv.Kind())
	}

	// Step 3: call toPtr – this *must* execute the “rv = rv.Elem()” line.
	ptr := toPtr(rv)

	// Verify the pointer is correct and points to the original int.
	if ptr.Kind() != reflect.Ptr {
		t.Fatalf("expected pointer kind, got %v", ptr.Kind())
	}
	if got := ptr.Elem().Int(); got != 456 {
		t.Fatalf("value mismatch: got %d want 456", got)
	}
}
