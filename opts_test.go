package asn1plus

import (
	"fmt"
	"reflect"
	"testing"
)

func ExampleOptions_byParse() {
	opts, err := NewOptions(`asn1:"tag:7,application"`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(opts)
	// Output: tag:7,application

}

func ExampleOptions_byAssembly() {
	opts := Options{}
	opts.SetClass(1)
	opts.SetTag(11)
	opts.Explicit = true
	fmt.Println(opts)
	// Output: tag:11,application,explicit
}

func TestOptions_codecov(_ *testing.T) {
	opts, _ := NewOptions(`asn1:"utf8,printable,fargus,tag:3"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"blarg,fargus,tag:3"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"tag:3,optional,omitempty"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"teletex,tag:-13"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"private,tag:1"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"private,tag:1,set"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"application,tag:2,default:5"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"application,tag:2,default:true"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"application,tag:2,default:thanks"`)
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"application,constraint:fakeConstraint,tag:2,default:thanks"`)
	_ = opts.String()
	opts.Default = struct{}{}
	_ = opts.String()
	opts, _ = NewOptions(`asn1:"application,tag:2,default:thanks"`)
	_ = opts.String()
	field := reflect.StructField{Tag: "blarg"}
	_, _ = NewOptions("asn1:")
	_, _ = extractOptions(field, 0, false)
	_ = defaultOptions()

	opts.Constraints = []string{`fakeConstraint`}
	opts.writeClassToken("context-specific")
	opts.setBool("automatic")
	opts.setBool("indefinite")
	_ = opts.String()
	opts.Default = struct{}{}
	opts.parseOptionDefault("")
	field = reflect.StructField{Name: "field", Tag: `asn1:"automatic,explicit"`}
	extractOptions(field, 0, true)
}
