package asn1plus

import "testing"

type testAttributeValueAssertion struct {
	Desc  OctetString
	Value OctetString
}

type testFilterPresent struct {
	Desc OctetString
}

func (r testFilterPresent) isFilter() {}

type testFilterInterface interface {
	isFilter()
}

type testEqualityMatch testAttributeValueAssertion

func (r testEqualityMatch) isFilter() {}

type testFilterAnd []testFilterInterface

func (r testFilterAnd) isFilter() {}

func TestChoice_SetOfChoice(t *testing.T) {
	testFilterChoices := NewChoices()
	o := &Options{Explicit: true}

	testFilterChoices.Register((*testFilterInterface)(nil), testFilterAnd{}, o.SetTag(0))
	testFilterChoices.Register((*testFilterInterface)(nil), testEqualityMatch{}, o.SetTag(3))
	testFilterChoices.Register((*testFilterInterface)(nil), testFilterPresent{}, o.SetTag(7))
	RegisterChoices("filter", testFilterChoices)

	present := testFilterPresent{Desc: OctetString("objectClass")}
	eqMatch := testEqualityMatch(testAttributeValueAssertion{Desc: OctetString("cn"), Value: OctetString("Bill Smith")})
	and := testFilterAnd{present, eqMatch}
	opts := Options{Choices: "filter"}

	hexes := map[EncodingRule]string{
		BER: "A0 27 3125A70F300D040B6F626A656374436C617373A31230100402636E040A42696C6C20536D697468",
		CER: "A0 27 3125A31230100402636E040A42696C6C20536D697468A70F300D040B6F626A656374436C617373", // canonical ordering
		DER: "A0 27 3125A31230100402636E040A42696C6C20536D697468A70F300D040B6F626A656374436C617373", // canonical ordering
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(and, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}

		want := hexes[rule]
		if got := pkt.Hex(); got != want {
			t.Fatalf("%s failed [%s encoding mismatch]:\n\twant: '%s'\n\tgot:  '%s'",
				t.Name(), rule, want, got)
		}

		var F2 testFilterInterface
		if err = Unmarshal(pkt, &F2, With(opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
	}

	UnregisterChoices("filter")
}

func TestChoice_SequenceOfChoice(t *testing.T) {
	type substringAssertion struct {
		Initial OctetString   `asn1:"tag:0"`     // occurs at most once
		Any     []OctetString `asn1:"tag:1,set"` // zero or more occurrences
		Final   OctetString   `asn1:"tag:2"`     // occurs at most once
	}

	// helper to build a tagged, explicit Choice
	makeChoice := func(tag int, val OctetString) Choice {
		return NewChoice(val, tag)
	}

	// build the input
	sa := substringAssertion{
		Initial: OctetString("thi"),
		Any:     []OctetString{OctetString("is"), OctetString("a"), OctetString("subs")},
		Final:   OctetString("ring"),
	}

	var seq []Choice
	if len(sa.Initial) > 0 {
		seq = append(seq, makeChoice(0, sa.Initial))
	}
	for _, part := range sa.Any {
		seq = append(seq, makeChoice(1, part))
	}
	if len(sa.Final) > 0 {
		seq = append(seq, makeChoice(2, sa.Final))
	}

	// register the CHOICE alternatives under a named registry
	choices := NewChoices()
	chopts := &Options{Explicit: true}
	choices.Register(nil, OctetString(""), chopts.SetTag(0))
	choices.Register(nil, OctetString(""), chopts.SetTag(1))
	choices.Register(nil, OctetString(""), chopts.SetTag(2))
	RegisterChoices("substring", choices)

	opts := &Options{Choices: "substring"}

	// BER‐encode our sequence of Choice
	pkt, err := Marshal(seq, With(opts))
	if err != nil {
		t.Fatalf("BER encoding failed: %v", err)
	}

	// UNmarshal directly into []OctetString
	var decoded []OctetString
	if err := Unmarshal(pkt, &decoded, With(opts)); err != nil {
		t.Fatalf("BER decoding failed: %v", err)
	}

	// expected values, with proper conversions
	want := []OctetString{
		OctetString("thi"),
		OctetString("is"),
		OctetString("a"),
		OctetString("subs"),
		OctetString("ring"),
	}
	if !deepEq(decoded, want) {
		t.Fatalf("decoded = %v; want %v", decoded, want)
	}
}

func TestSequence_choiceAutomaticTagging(t *testing.T) {
	o := Options{Explicit: true}

	choices := NewChoices(true) // engage auto tagging
	choices.Register(nil, ObjectIdentifier{})
	choices.Register(nil, Integer{}, o.SetTag(7))
	choices.Register(nil, EmbeddedPDV{})
	RegisterChoices("myChoices", choices)

	type MySequence struct {
		Field0 PrintableString
		Field1 Integer
		Field2 Choice      `asn1:"choices:myChoices"`
		Field3 OctetString `asn1:"optional"`
	}

	oid, _ := NewObjectIdentifier(1, 3, 6, 1, 4, 1, 56521)
	choice := NewChoice(oid) // no tag needed :)

	nint, _ := NewInteger(3)

	mine := MySequence{
		Field0: PrintableString("Hello"),
		Field1: nint,
		Field2: choice,
	}

	pkt, err := Marshal(mine, With(BER))
	if err != nil {
		t.Fatalf("%s failed [BER encoding]: %v", t.Name(), err)
	}
	//t.Logf("Encoded packet: %s\n", pkt.Hex())

	var mine2 MySequence
	if err = Unmarshal(pkt, &mine2); err != nil {
		t.Fatalf("%s failed [BER decoding]: %v", t.Name(), err)
	}

	//t.Logf("%#v\n", mine2)
	UnregisterChoices("myChoices")

	// coverage
	//marshalSequenceChoiceField(&Options{}, Choice{Value: OctetString("hi"), Explicit: true}, pkt)
}

func TestEmbeddedPDV_encodingRulesChoiceSyntaxes(t *testing.T) {
	abstract, _ := NewObjectIdentifier(2, 1, 2, 1, 2, 1, 2, 1)
	transfer, _ := NewObjectIdentifier(2, 0, 2, 0, 2, 0, 2, 0)
	syntaxes := Syntaxes{abstract, transfer}

	pdv := EmbeddedPDV{
		Identification:      NewChoice(syntaxes, 0),
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	hexes := map[EncodingRule]string{
		BER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		CER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
		DER: "6B 23 A01430120607510201020102010607500200020002000704746573740405626C617267",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, With(rule))
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

		if newPDV.Identification.Value() == nil {
			t.Fatalf("Missing identification choice after decoding")
		}

		switch id := newPDV.Identification.Value().(type) {
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

	pdv := EmbeddedPDV{
		Identification:      NewChoice(oid, 4),
		DataValueDescriptor: ObjectDescriptor("test"),
		DataValue:           OctetString("blarg"),
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(pdv, With(rule))
		if err != nil {
			t.Fatalf("%s failed [%s encode]: %v", t.Name(), rule, err)
		}

		//t.Logf("%s PKT Hex: %s\n", rule, pkt.Hex())

		var newPDV EmbeddedPDV
		if err = Unmarshal(pkt, &newPDV); err != nil {
			t.Fatalf("%s failed [%s decode]: %v", t.Name(), rule, err)
		}

		// Now "unpack" the decoded identification field.
		if newPDV.Identification.Value() == nil {
			t.Fatalf("%s failed [%s field check]: Missing identification choice after decoding",
				t.Name(), rule)
		}

		switch id := newPDV.Identification.Value().(type) {
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
	choices := NewChoices(true)
	o := &Options{Explicit: true}

	choices.Register(nil, Integer{}, o)          // -> [0] EXPLICIT
	choices.Register(nil, ObjectIdentifier{}, o) // -> [1] EXPLICIT
	RegisterChoices("blarg", choices)

	// Sanity-check the tags that were minted.
	if !choices.Choose(Integer{}, 0) {
		t.Fatalf("first alternative did not get automatic tag 0")
	}
	if !choices.Choose(ObjectIdentifier{}, 1) {
		t.Fatalf("second alternative did not get automatic tag 1")
	}

	// Now encode the OID and ensure the outer
	// tag is *explicit*.
	oid, _ := NewObjectIdentifier(1, 3, 6)
	ch := NewChoice(oid, 1)
	pkt, err := Marshal(ch, With(BER, &Options{Choices: "blarg"})) // marshal the CHOICE itself
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// 0xA1 == [1] constructed (EXPLICIT)
	if pkt.Data()[0] != 0xA1 {
		t.Fatalf("automatic tag should be EXPLICIT (A1), got 0x%02X", pkt.Data()[0])
	}
	UnregisterChoices("blarg")
}

func TestChoice_SequenceUniversal(t *testing.T) {
	// 1) Build a Choices registry with two SEQUENCE‐typed alternatives:
	//    Alt1 == SEQUENCE {A INTEGER}, Alt2 == SEQUENCE {A INTEGER; B INTEGER}
	seqChoices := NewChoices()     // no auto‐tag, UNIVERSAL tags
	o := &Options{Explicit: false} // explicit=false → alternatives encoded as bare SEQUENCE
	type Alt1 struct{ A Integer }
	type Alt2 struct {
		A Integer
		B Integer
	}
	seqChoices.Register(nil, Alt1{}, o.SetTag(0))
	seqChoices.Register(nil, Alt2{}, o.SetTag(1))
	RegisterChoices("sequniv", seqChoices)
	defer UnregisterChoices("sequniv")

	// 2) Create a wrapper that holds a CHOICE untagged:
	type Wrapper struct {
		C Choice `asn1:"choices:sequniv"`
	}

	three, _ := NewInteger(3)
	seven, _ := NewInteger(7)

	// pick variant #2 for the test:
	w := Wrapper{
		C: NewChoice(Alt2{A: three, B: seven}, 1),
	}

	opts := Options{Choices: "sequniv"}

	// 3) Round‐trip each encoding rule, comparing hex and then unmarshalling
	hexes := map[EncodingRule]string{
		BER: "30 0A A1083006020103020107",
		CER: "30 0A A1083006020103020107",
		DER: "30 0A A1083006020103020107",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(w, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}
		got := pkt.Hex()
		want := hexes[rule]
		if got != want {
			t.Fatalf("%s failed [%s encoding]: want %q, got %q", t.Name(), rule, want, got)
		}

		// now decode
		var w2 Wrapper
		if err := Unmarshal(pkt, &w2, With(rule, opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}

		// assert we got Alt2 back
		alt2, ok := w2.C.Value().(Alt2)
		if !ok {
			t.Fatalf("%s: decoded C is %T, want Alt2", t.Name(), w2.C.Value)
		}
		if alt2.A.Big().Cmp(three.Big()) != 0 || alt2.B.Big().Cmp(seven.Big()) != 0 {
			t.Errorf("%s: wrong Alt2 fields: %+v", t.Name(), alt2)
		}
	}
}

func TestChoice_DefaultInterfaceDecode(t *testing.T) {
	def := NewChoices(false)       // no auto‐tag, bare UNIVERSAL tags
	o := &Options{Explicit: false} // alternatives will be unwrapped
	def.Register(nil, ObjectIdentifier{}, o.SetTag(0))
	def.Register(nil, OctetString(""), o.SetTag(1))
	RegisterChoices("defintf", def)
	defer UnregisterChoices("defintf")

	type Wrapper struct {
		C Choice `asn1:"choices:defintf"`
	}
	wantVal := OctetString("hello")
	w := Wrapper{C: NewChoice(wantVal, 1)}
	opts := Options{Choices: "defintf"}

	hexes := map[EncodingRule]string{
		BER: "30 09 A107040568656C6C6F",
		CER: "30 09 A107040568656C6C6F",
		DER: "30 09 A107040568656C6C6F",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(w, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}
		got := pkt.Hex()
		want := hexes[rule]
		if got != want {
			t.Fatalf("%s failed [%s encoding mismatch]:\n\twant: %q\n\tgot:  %q",
				t.Name(), rule, want, got)
		}

		var w2 Wrapper
		if err := Unmarshal(pkt, &w2, With(rule, opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
		str, ok := w2.C.Value().(OctetString)
		if !ok || string(str) != string(wantVal) {
			t.Fatalf("%s: decoded = %#v (type %T), want OctetString(%q)",
				t.Name(), w2.C.Value(), w2.C.Value(), wantVal)
		}
	}
}

func TestChoice_BareSetChoiceUniversal(t *testing.T) {
	setuniv := NewChoices(false)   // no auto‐tag
	o := &Options{Explicit: false} // bare UNIVERSAL SET OF
	type Alt1 struct{ A Integer }
	type Alt2 struct {
		A Integer
		B Integer
	}
	setuniv.Register(nil, Alt1{}, o.SetTag(0))
	setuniv.Register(nil, Alt2{}, o.SetTag(1))
	RegisterChoices("setuniv", setuniv)
	defer UnregisterChoices("setuniv")

	type Wrapper struct {
		C Choice `asn1:"set,choices:setuniv"`
	}

	five, _ := NewInteger(5)
	nine, _ := NewInteger(9)

	wantAlt := Alt2{A: five, B: nine}
	w := Wrapper{C: NewChoice(wantAlt, 1)}
	opts := Options{Choices: "setuniv"}

	hexes := map[EncodingRule]string{
		BER: "30 0A A1083006020105020109",
		CER: "30 0A A1083006020105020109",
		DER: "30 0A A1083006020105020109",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(w, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}
		got := pkt.Hex()
		want := hexes[rule]
		if got != want {
			t.Fatalf("%s failed [%s encoding mismatch]:\n\twant: %q\n\tgot:  %q",
				t.Name(), rule, want, got)
		}

		var w2 Wrapper
		if err := Unmarshal(pkt, &w2, With(rule, opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
		alt2, ok := w2.C.Value().(Alt2)
		if !ok {
			t.Fatalf("%s: got %T, want Alt2", t.Name(), w2.C.Value)
		}
		if alt2.A.Big().Cmp(five.Big()) != 0 || alt2.B.Big().Cmp(nine.Big()) != 0 {
			t.Errorf("%s: wrong fields %+v", t.Name(), alt2)
		}
	}
}

// -----------------------------------------------------------------------------
// 1) bare UNIVERSAL SEQUENCE  → decodeSeqChoice
func TestChoice_SeqChoice_Direct(t *testing.T) {
	// build a Choices registry with two SEQUENCE‐typed alts
	seqCh := NewChoices(false)     // no auto‐tag
	o := &Options{Explicit: false} // bare UNIVERSAL encoding
	type Alt1 struct{ A Integer }
	type Alt2 struct {
		A Integer
		B Integer
	}
	seqCh.Register(nil, Alt1{}, o.SetTag(0))
	seqCh.Register(nil, Alt2{}, o.SetTag(1))
	RegisterChoices("seqdir", seqCh)
	defer UnregisterChoices("seqdir")

	// pick the second alternative
	one, _ := NewInteger(1)
	two, _ := NewInteger(2)
	in := Alt2{A: one, B: two}
	ch := NewChoice(in, 1)

	opts := Options{Choices: "seqdir"}

	hexes := map[EncodingRule]string{
		BER: "A1 08 3006020101020102",
		CER: "A1 08 3006020101020102",
		DER: "A1 08 3006020101020102",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(ch, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}
		got := pkt.Hex()
		want := hexes[rule]
		if got != want {
			t.Fatalf("%s failed [%s encoding mismatch]:\n\twant: %q\n\tgot:  %q",
				t.Name(), rule, want, got)
		}

		var out Choice
		if err := Unmarshal(pkt, &out, With(rule, opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
		alt2, ok := out.Value().(Alt2)
		if !ok {
			t.Fatalf("%s: decoded type %T, want Alt2", t.Name(), out.Value())
		}
		if alt2.A.Big().Cmp(one.Big()) != 0 || alt2.B.Big().Cmp(two.Big()) != 0 {
			t.Fatalf("%s: wrong fields %+v", t.Name(), alt2)
		}
	}
}

func TestChoice_DefaultInterfaceDecode_Primitive(t *testing.T) {
	def := NewChoices(false)
	o := &Options{Explicit: false}
	def.Register(nil, PrintableString(""), o.SetTag(0))
	def.Register(nil, Integer{}, o.SetTag(1))
	RegisterChoices("primdir", def)
	defer UnregisterChoices("primdir")

	// choose the PrintableString branch (tag=0)
	wantPS := PrintableString("foobar")
	ch := NewChoice(wantPS, 0)

	opts := Options{Choices: "primdir"}

	hexes := map[EncodingRule]string{
		BER: "A0 08 1306666F6F626172",
		CER: "A0 08 1306666F6F626172",
		DER: "A0 08 1306666F6F626172",
	}

	for _, rule := range encodingRules {
		pkt, err := Marshal(ch, With(rule, opts))
		if err != nil {
			t.Fatalf("%s failed [%s encoding]: %v", t.Name(), rule, err)
		}
		got := pkt.Hex()
		want := hexes[rule]
		if got != want {
			t.Fatalf("%s failed [%s encoding mismatch]:\n\twant: %q\n\tgot:  %q",
				t.Name(), rule, want, got)
		}

		var out Choice
		if err := Unmarshal(pkt, &out, With(rule, opts)); err != nil {
			t.Fatalf("%s failed [%s decoding]: %v", t.Name(), rule, err)
		}
		ps, ok := out.Value().(PrintableString)
		if !ok || ps != wantPS {
			t.Fatalf("%s: decoded = %#v (type %T), want PrintableString(%q)",
				t.Name(), out.Value(), out.Value(), wantPS)
		}
	}
}

func TestChoice_codecov(_ *testing.T) {
	var ch invalidChoice
	ch.Tag()
	ch.Value()
	ch.isChoice()

	var wr wrappedChoice
	wr.isChoice()

	var cho Choices = NewChoices()
	cho.lookupDescriptorByInterface(refTypeOf(struct{}{}))
	cho.Choose(struct{}{})
}

func init() {
	testFilterChoices := NewChoices()
	o := &Options{Explicit: true}

	testFilterChoices.Register((*testFilterInterface)(nil), testFilterAnd{}, o.SetTag(0))
	testFilterChoices.Register((*testFilterInterface)(nil), testEqualityMatch{}, o.SetTag(3))
	testFilterChoices.Register((*testFilterInterface)(nil), testFilterPresent{}, o.SetTag(7))
	RegisterChoices("filter", testFilterChoices)
}
