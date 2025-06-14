package asn1plus

/*
choice.go contains all functionality pertaining to the ASN.1 CHOICE
type.
*/

import "reflect"

/*
Choice implements a "transport" mechanism for ASN.1 CHOICE types
residing within compound types (e.g.: SEQUENCES). For example:

	 type MyStruct struct {
		SomeField Choice
		.. other fields ..
	 }

We can create an instance of Choice as simply as:

	fieldTagInteger := 2
	myChoice := Choice{Value:<any>, Tag:&fieldTagInteger}

... or, alternatively ...

	myChoice := Choice{Value:<any>}
	myChoice.SetTag(2)

Finally, we place our Choice within the compound instance in question
prior to encoding via the [Marshal] function.

	 mine := myStruct{
		SomeField: myChoice,
	 }

Here, we used an instance of Choice to specify the "chosen" value
and (if needed) the pointer to an integer (e.g.: for a field tag
such as [2]). Use of a tag is only necessary if the list of available
[Choices] contains more than one instance of a single type, which
would otherwise lead to an ambiguous Choice state.  For an example
of this in the real world, see the [EmbeddedPDV] ASN.1 schema definition.
*/
type Choice struct {
	Value any
	Tag   *int // for field tagging
}

/*
SetTag assigns the integer tag to the receiver instance. This
is merely a convenient alternative to manually setting the
struct field with an integer pointer instance.
*/
func (r *Choice) SetTag(tag int) {
	if r != nil {
		r.Tag = new(int)
		(*r.Tag) = tag
	}
}

/*
IsZero returns a Boolean value indicative of a nil value state.
*/
func (r *Choice) IsZero() bool {
	var is bool = true
	if r != nil {
		is = r.Value == nil
	}

	return is
}

type choiceAlternative struct {
	Type reflect.Type  // the Go type of the alternative
	Opts choiceOptions // options which help match the correct choice
}

/*
Choices implements a [Choice] registry. See [Choices.Register] for a means of
declaring alternatives from which a [Choice] may be made. See [Choices.Choose]
for a means of verifying the chosen [Choice].
*/
type Choices struct {
	alts []choiceAlternative
}

/*
NewChoices allocates and returns an instance of [Choices]. See [Choices.Register]
and [Choices.Choose] for a means of interacting with the return instance.
*/
func NewChoices() (c Choices) {
	c.alts = make([]choiceAlternative, 0)
	return
}

/*
Register returns an error following an attempt to register an instance of [Choice],
associated with the tag options provided, to the receiver instance.

Tag options can be used to declare the configuration used to choose a particular
choice, e.g.:

  - "choice:schemaFieldName"
  - "choice:schemaFieldName,tag:2"
*/
func (r *Choices) Register(instance any, opts ...string) error {
	if instance == nil {
		return mkerr("cannot register nil instance; hint: for ASN.1 NULL, use Null type")
	}

	var options choiceOptions
	if len(opts) > 0 {
		options = tokenizeChoiceOptions(opts[0])
	}

	r.alts = append(r.alts, choiceAlternative{
		Type: derefTypePtr(reflect.TypeOf(instance)),
		Opts: options,
	})

	return nil
}

/*
Len returns the integer number of registered [Choice] instances present within
the receiver instance.
*/
func (r Choices) Len() int { return len(r.alts) }

func (r Choices) byTag(tag int) (calt choiceAlternative, ok bool) {
	for _, alt := range r.alts {
		if alt.Opts.Tag == tag {
			calt = alt
			ok = true
			break
		}
	}
	return
}

/*
Choose returns the input instance of [Choice] alongside an error following an attempt
to match the specific [Choice] and optional identifier (id) with a registered [Choice]
residing within the receiver instance.

Choose checks whether the given user-supplied instance (along with its ASN.1 tag)
matches one of the registered alternatives. It does so by comparing both the tag
and the Go type (using reflection).

The registered alternative is returned if exactly one match is found. If no alternatives
match or if more than one candidate is found (which may happen if multiple entries use the
same type and tag) an error is returned.
*/
func (r Choices) Choose(instance any, opts ...string) (c Choice, err error) {
	var (
		mID bool
		o   choiceOptions
	)

	if len(opts) > 0 {
		o = tokenizeChoiceOptions(opts[0])
		mID = true
	}

	matchID := func(alt choiceAlternative) (matched bool) {
		if o.Name != "" {
			matched = alt.Opts.Name == o.Name && alt.Opts.Tag == o.Tag
		} else {
			matched = alt.Opts.Tag == o.Tag
		}

		return
	}

	if instance == nil {
		err = errorNilInput
		return
	}

	inputType := derefTypePtr(reflect.TypeOf(instance))
	var matches []choiceAlternative

	for _, alt := range r.alts {
		if inputType == alt.Type {
			if mID {
				if matchID(alt) {
					matches = append(matches, alt)
				}
			} else {
				matches = append(matches, alt)
			}
		}
	}

	switch len(matches) {
	case 0:
		err = errorNoChoiceMatched(inputType.String())
	case 1:
		c = Choice{Value: instance, Tag: &o.Tag}
	default:
		err = errorAmbiguousChoice
	}

	return
}

/*
getChoiceMethod returns an instance of func() Choices. This is used to extract
an instance of Choices containing any number of choiceAlternative instances.
Any struct which contains a field of type Choice, i.e.:

	type MyStruct struct {
	       FieldName Choice `... any asn1 tags ...`
	}

... MUST create a method extended by this type and bearing the name:

	<FieldName>Choices

... where <FieldName> is the actual case-accurate struct field string name,
and is prepended to the "Choices" literal string.

The method is niladic and returns only one (1) value: an instance of Choices.

Thus, MyStruct would extend:

	FieldNameChoices() Choices

Naturally the return Choices instance should contain one or more empty pointer
values, each of a valid alternative type (e.g.: OctetString). For instance:

	Choice := {
	      new(TypeName),
	      new(OtherType),
	      &ThisWorksTooForSomeTypes{},
	      ....
	}

The return type is tailored for the field it is meant to facilitate. This
method naming requirement exists because it is possible for a single struct
to contain multiple fields that are all of the choiceAlternative type, thus
there needed to be a way to differentiate them.
*/
func getChoicesMethod(field string, x any) (func() Choices, bool) {
	v := reflect.ValueOf(x)
	method := v.MethodByName(field + "Choices")
	if !method.IsValid() {
		return nil, false
	}

	mType := method.Type()
	if mType.NumIn() != 0 || mType.NumOut() != 1 {
		return nil, false
	}

	choicesType := reflect.TypeOf((*Choices)(nil)).Elem()
	if !mType.Out(0).AssignableTo(choicesType) {
		return nil, false
	}

	choicesFunc := func() Choices {
		results := method.Call(nil)
		return results[0].Interface().(Choices)
	}

	return choicesFunc, true
}

func callChoicesMethod(n string, constructed any, pkt Packet, opts Options) (alt Choice, err error) {
	meth, found := getChoicesMethod(n, constructed)
	if !found {
		err = errorNoChoicesMethod(n)
		return
	}

	var candidate any
	var structTag string
	switch pkt.Type() {
	case BER, DER:
		// Extract the outer TLV from the Packet.
		var tlv TLV
		if tlv, err = pkt.TLV(); err == nil {
			pkt.SetOffset(pkt.Offset() + tlv.Length)
			// IMPORTANT: Extract the explicit context tag from the outer TLV.
			// This ensures that the opts used for choosing the candidate get a valid tag.
			extractedTag := tlv.Tag // For example, if identifier is 0xA4, then extractedTag will be 4.
			// Build a structTag string that will be used for candidate matching.
			opts.Tag = extractedTag // Now opts.Tag is properly set (instead of -1).
			structTag = "choice:tag:" + itoa(opts.Tag)
			candidate, err = chooseChoiceCandidateBER(n, constructed, pkt, tlv, meth(), opts)
		}
	default:
		err = mkerr("Encoding rule not supported")
	}

	if err == nil {
		alt, err = meth().Choose(candidate, structTag)
	}

	return
}

func chooseChoiceCandidateBER(n string, constructed any, pkt Packet, tlv TLV, choices Choices, opts Options) (candidate any, err error) {
	// Lookup the candidate alternative using opts.Tag (set by callChoicesMethod)
	alt, ok := choices.byTag(opts.Tag)
	if !ok {
		return nil, mkerr("unknown choice tag " + itoa(opts.Tag))
	}

	// Allocate a new instance of the candidate type.
	candidateInst := reflect.New(alt.Type).Interface()

	if isPrimitive(candidateInst) {
		contentLen := tlv.Length
		candidateContent := pkt.Data()[2 : 2+contentLen]

		sub := pkt.Type().New(byte(alt.Opts.UTag))
		sub.Append(pkt.Data()[1:]...)
		sub.SetOffset(pkt.Offset())
		opts.Tag = alt.Opts.UTag
		pkt = sub

		subTLV := pkt.Type().newTLV(0, alt.Opts.UTag, tlv.Length, tlv.Compound, candidateContent...)
		if reader, ok := candidateInst.(asn1Reader); ok {
			err = reader.read(pkt, subTLV, opts)
		} else {
			err = mkerr("Primitive has no read method")
		}
	} else {
		sub := pkt.Type().New(pkt.Data()...)
		sub.SetOffset(0)
		if _, err = sub.TLV(); err == nil {
			// IMPORTANT: Clear the tag override before decoding inner fields.
			// This allows inner decoders (for, say, ObjectIdentifier) to use
			// their natural universal tag.
			opts.Tag = -1
			err = unmarshalValue(sub, reflect.ValueOf(candidateInst), opts)
		}
	}

	if err == nil {
		// Dereference the candidate instance (allocated as a pointer) and return it.
		candidate = reflect.ValueOf(candidateInst).Elem().Interface()
	}

	return
}

type choiceOptions struct {
	Name string // name of choice per ASN.1 schema
	Tag, // ASN.1 context tag
	UTag int // ASN.1 tag number
}

func tokenizeChoiceOptions(opts string) (options choiceOptions) {
	options.Tag, options.UTag = -1, -1
	if opts = lc(opts); hasPfx(opts, "choice:") {
		sp := split(trimPfx(opts, "choice:"), `,`)
		for _, slice := range sp {
			switch {
			case hasPfx(slice, "tag:"):
				if t, err := atoi(trimPfx(slice, "tag:")); err == nil && options.Tag == -1 {
					options.Tag = t
				}
			case hasPfx(slice, "universal-tag:"):
				if t, err := atoi(trimPfx(slice, "universal-tag:")); err == nil && options.UTag == -1 {
					options.UTag = t
				}
			default:
				if options.Name == "" {
					options.Name = slice
				}
			}
		}
	}

	return
}
