package asn1plus

import (
	"fmt"
	"testing"
)

func TestChoice_ContextTagging(t *testing.T) {
	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	tagVal := "choice:tag:3"
	tagName := "choice:fieldName3"

	ambiguousByTag := NewChoices()
	ambiguousByTag.Register(new(ObjectIdentifier), "choice:tag:0")
	ambiguousByTag.Register(new(ObjectIdentifier), "choice:tag:1")
	ambiguousByTag.Register(new(ObjectIdentifier), "choice:tag:2")
	ambiguousByTag.Register(new(ObjectIdentifier), "choice:tag:3")
	ambiguousByTag.Register(new(ObjectIdentifier), "choice:tag:4")

	choice, err := ambiguousByTag.Choose(oid, tagVal)
	if err != nil {
		t.Fatalf("%s failed [tag selection error]: %v", t.Name(), err)
	} else if choice.Value.(ObjectIdentifier).String() != `1.3.6.1.4.1.56521` {
		t.Fatalf("Could not choose AUTOMATIC tag OID by tag")
	}

	ambiguousByName := NewChoices()
	ambiguousByName.Register(new(ObjectIdentifier), "choice:fieldName0")
	ambiguousByName.Register(new(ObjectIdentifier), "choice:fieldName1")
	ambiguousByName.Register(new(ObjectIdentifier), "choice:fieldName2")
	ambiguousByName.Register(new(ObjectIdentifier), "choice:fieldName3")
	ambiguousByName.Register(new(ObjectIdentifier), "choice:fieldName4")

	choice, err = ambiguousByName.Choose(oid, tagName)
	if err != nil {
		t.Fatalf("%s failed [name selection error]: %v", t.Name(), err)
	} else if choice.Value.(ObjectIdentifier).String() != `1.3.6.1.4.1.56521` {
		t.Fatalf("Could not choose AUTOMATIC tag OID by name")
	}
}

/*
This example demonstrates the creation of the following ASN.1 CHOICE per [ITU-T Rec. X.501].

	DirectoryString{INTEGER:maxSize} ::= CHOICE {
	        teletexString TeletexString(SIZE (1..maxSize,...)),
	        printableString PrintableString(SIZE (1..maxSize,...)),
	        bmpString BMPString(SIZE (1..maxSize,...)),
	        universalString UniversalString(SIZE (1..maxSize,...)),
	        uTF8String UTF8String(SIZE (1..maxSize,...)) }

Following this, a [T61String] is chosen from our available directory string choices.

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func ExampleChoice_t61DirectoryStringDER() {
	// Marshal new T61String
	t61, err := NewT61String(`HELLO WORLD`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create our ASN.1 CHOICE(s)
	directoryString := NewChoices()
	_ = directoryString.Register(new(T61String))
	_ = directoryString.Register(new(PrintableString))
	_ = directoryString.Register(new(BMPString))
	_ = directoryString.Register(new(UniversalString))
	_ = directoryString.Register(new(UTF8String))

	// Choose our DirectoryString if the
	// T.61 tag (20) is matched
	var choice Choice
	if choice, err = directoryString.Choose(t61); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(choice.Value)
	// Output: HELLO WORLD
}

/*
This example demonstrates the creation of the following ASN.1 CHOICE per [ITU-T Rec. X.501]:

	DirectoryString{INTEGER:maxSize} ::= CHOICE {
	        teletexString TeletexString(SIZE (1..maxSize,...)),
	        printableString PrintableString(SIZE (1..maxSize,...)),
	        bmpString BMPString(SIZE (1..maxSize,...)),
	        universalString UniversalString(SIZE (1..maxSize,...)),
	        uTF8String UTF8String(SIZE (1..maxSize,...)) }

In this example, we create the ASN.1 CHOICE instance, but supply an ineligible type
(an ASN.1 BIT STRING) to demonstrate that the effective ASN.1 tag of a CHOICE is used to
determine the correct [Choice].

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func ExampleChoice_invalidChoice() {
	// Create an ASN.1 BIT STRING (tag 3), which is
	// INAPPROPRIATE for a DirectoryString.
	bs, err := NewBitString(`'1010011'B`)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create our ASN.1 CHOICE(s) per the X.501
	// schema definition.
	directoryString := NewChoices()
	directoryString.Register(new(T61String))
	directoryString.Register(new(PrintableString))
	directoryString.Register(new(BMPString))
	directoryString.Register(new(UniversalString))
	directoryString.Register(new(UTF8String))

	if _, err = directoryString.Choose(bs); err != nil {
		fmt.Println(err)
	}
	// Output: no matching alternative found for input type asn1plus.BitString
}

func ExampleChoice_encodeBareChoice() {
	var choice Choice = Choice{Value: Null{}}
	pkt, err := Marshal(choice)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("CHOICE hex: %s\n", pkt.Hex())
	// Output: CHOICE hex: 05 00
}

func TestChoice_codecov(_ *testing.T) {
	var choices Choices = NewChoices()
	choices.Len()
	choices.Register(nil)
	choices.Choose(nil)
}
