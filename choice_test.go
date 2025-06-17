package asn1plus

import (
	"fmt"
	"sync"
	"testing"
)

func TestChoice_ContextTagging(t *testing.T) {
	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	tagVal := "choice:tag:3"

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

func TestSequence_choiceAutomaticTagging(t *testing.T) {
	choices := NewChoices(Options{Automatic: true})
	choices.Register(new(ObjectIdentifier))
	choices.Register(&Integer{}, "choice:tag:7")
	choices.Register(&EmbeddedPDV{})

	opts := Options{ChoicesMap: map[string]Choices{
		`myChoices`: choices,
	}}

	type MySequence struct {
		Field0 PrintableString
		Field1 int    `asn1:"integer"`
		Field2 Choice `asn1:"choices:myChoices"`
		Field3 string `asn1:"octet,optional"`
	}

	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	choice := Choice{Value: oid}
	choice.SetTag(0)

	mine := MySequence{
		Field0: PrintableString("Hello"),
		Field1: 3,
		Field2: choice,
	}

	pkt, err := Marshal(mine, WithEncoding(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}
	t.Logf("Encoded packet: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2, WithOptions(opts)); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}
	//t.Logf("%s\n", mine2.Field2.Value.(ObjectIdentifier))

	// coverage
	marshalSequenceChoiceField(Options{}, Choice{Value:OctetString("hi"), Explicit:true}, pkt, pkt, 1)
}

func TestEmbeddedPDV_encodingRulesChoiceSyntaxes(t *testing.T) {
	abstract, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	transfer, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)
	syntaxes := Syntaxes{abstract, transfer}

	tag := 0
	choice := Choice{Value: &syntaxes, Tag: &tag}

	pdv := EmbeddedPDV{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	hexes := map[EncodingRule]string{
		BER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		want := hexes[rule]
		if got := pkt.Hex(); got != want {
			t.Fatalf("%s failed [%s encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		if newPDV.Identification.IsZero() {
			t.Fatalf("Missing identification choice after decoding")
		}

		switch id := newPDV.Identification.Value.(type) {
		case Syntaxes:
			if id.Abstract.String() != `2.1.2.1.2.1.2.1` ||
				id.Transfer.String() != `2.0.2.0.2.0.2.0` {
				t.Fatalf("%s failed: expected Syntaxes{ Abstract: 2.1.2.1.2.1.2.1 Transfer: 2.0.2.0.2.0.2.0 }, got %#v",
					t.Name(), id)
			}
		default:
			t.Fatalf("Unexpected alternative type in identification: got %T", id)
		}

		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("DataValueDescriptor mismatch")
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("DataValue mismatch")
		}
	}
}

func TestExternal_encodingRulesChoiceSyntaxes(t *testing.T) {
	abstract, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	transfer, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)
	syntaxes := Syntaxes{abstract, transfer}

	tag := 0
	choice := Choice{Value: &syntaxes, Tag: &tag}

	pdv := External{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	hexes := map[EncodingRule]string{
		BER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "28 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		want := hexes[rule]
		if got := pkt.Hex(); got != want {
			t.Fatalf("%s failed [%s encoding mismatch]\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		if newPDV.Identification.IsZero() {
			t.Fatalf("Missing identification choice after decoding")
		}

		switch id := newPDV.Identification.Value.(type) {
		case Syntaxes:
			if id.Abstract.String() != `2.1.2.1.2.1.2.1` ||
				id.Transfer.String() != `2.0.2.0.2.0.2.0` {
				t.Fatalf("%s failed: expected Syntaxes{ Abstract: 2.1.2.1.2.1.2.1 Transfer: 2.0.2.0.2.0.2.0 }, got %#v",
					t.Name(), id)
			}
		default:
			t.Fatalf("Unexpected alternative type in identification: got %T", id)
		}

		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("DataValueDescriptor mismatch")
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("DataValue mismatch")
		}
	}
}

func TestEmbeddedPDV_encodingRulesChoiceOID(t *testing.T) {
	oid, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)

	choice := Choice{Value: &oid}
	choice.SetTag(4) // choice [4]

	pdv := EmbeddedPDV{
		Identification:      choice,
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, WithEncoding(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		t.Logf("%s PKT Hex: %s\n", rule, pkt.Hex())

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		// Now "unpack" the decoded identification field.
		if newPDV.Identification.IsZero() {
			t.Fatalf("%s failed [%s field check]: Missing identification choice after decoding",
				t.Name(), rule)
		}

		switch id := newPDV.Identification.Value.(type) {
		case ObjectIdentifier:
			// Compare the decoded OID with our original.
			if !id.Eq(oid) {
				t.Fatalf("%s failed [%s OID cmp.]: Decoding mismatch in identification: got %v; want %v",
					t.Name(), rule, id, oid)
			}
		default:
			t.Fatalf("%s failed [%s OID mismatch]: Unexpected alternative type in identification: got %T",
				t.Name(), rule, id)
		}

		if string(newPDV.DataValueDescriptor) != "test" {
			t.Fatalf("%s failed [%s DataValueDescriptor mismatch]: want test, got %v",
				t.Name(), rule, newPDV.DataValueDescriptor)
		} else if string(newPDV.DataValue) != "blarg" {
			t.Fatalf("%s failed [%s DataValue mismatch]: want blarg, got %v",
				t.Name(), rule, newPDV.DataValue)
		}
	}
}

func TestChoice_AutomaticTagsUniqueAndExplicit(t *testing.T) {
	// Automatic tags must be unique and EXPLICIT
	auto := NewChoices(Options{Automatic: true})
	auto.Register(new(Integer))          // -> [0] EXPLICIT
	auto.Register(new(ObjectIdentifier)) // -> [1] EXPLICIT

	// Sanity-check the tags that were minted.
	integer, _ := NewInteger(42)
	if alt, err := auto.Choose(integer, "choice:tag:0"); err != nil || *alt.Tag != 0 {
		t.Fatalf("first alternative did not get automatic tag 0")
	}
	if alt, err := auto.Choose(ObjectIdentifier{}, "choice:tag:1"); err != nil || *alt.Tag != 1 {
		t.Fatalf("second alternative did not get automatic tag 1")
	}

	// Now encode the OID and ensure the outer
	// tag is *explicit*.
	oid, _ := NewObjectIdentifier(1, 3, 6)
	ch, _ := auto.Choose(oid, "choice:tag:1")
	ch.Explicit = true
	pkt, err := Marshal(ch, WithEncoding(DER)) // marshal the CHOICE itself
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	// 0xA1 == [1] constructed (EXPLICIT)
	if pkt.Data()[0] != 0xA1 {
		t.Fatalf("automatic tag should be EXPLICIT (A1), got 0x%02X", pkt.Data()[0])
	}
}

func TestChoice_DuplicateTagCollision(t *testing.T) {
	// Duplicate tag registration should be rejected / ambiguous
	dup := NewChoices()
	_ = dup.Register(new(Integer), "choice:tag:0")
	_ = dup.Register(new(Boolean), "choice:tag:0")

	if err := dup.Register(new(Boolean), "choice:tag:0"); err == nil {
		t.Fatalf("expected duplicate-tag error, got nil")
	}
}

func TestChoice_NegativeTagLeak(t *testing.T) {
	choices := NewChoices()
	_ = choices.Register(new(ObjectIdentifier), "choice:tag:0")

	oid, _ := NewObjectIdentifier(1, 2, 3)
	ch := Choice{Value: oid}

	pkt, err := Marshal(ch, WithEncoding(DER))
	if err != nil {
		t.Fatalf("marshal failed unexpectedly: %v", err)
	}
	if pkt.Data()[0] != 0x06 {
		t.Fatalf("expected bare OBJECT IDENTIFIER (0x06), got 0x%02X",
			pkt.Data()[0])
	}
}

func TestChoice_ConcurrentUseDataRace(t *testing.T) {
	// Registry used concurrently must be race-safe
	// Run with: go test -race -run TestChoice_ConcurrentUseDataRace
	reg := NewChoices()
	_ = reg.Register(new(Integer), "choice:tag:0")

	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		integer, _ := NewInteger(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = reg.Choose(integer, "choice:tag:0")
		}()
	}
	wg.Wait()
	// With current mutable slice, the -race tool reports:
	// "WARNING: DATA RACE" (append while readers iterate).
}
