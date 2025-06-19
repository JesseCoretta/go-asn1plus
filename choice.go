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
	Value    any
	Tag      *int // for field tagging
	Explicit bool
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
	cfg   Options
	alts  []choiceAlternative
	tagIx map[int]int
}

/*
NewChoices allocates and returns an instance of [Choices]. See [Choices.Register]
and [Choices.Choose] for a means of interacting with the return instance.

The input options instance can be used to deliver an instance of [Options] which
contains an "Automatic" Boolean value of true.
*/
func NewChoices(opts ...Options) (c Choices) {
	if len(opts) > 0 {
		c.cfg = opts[0]
	}
	c.alts = make([]choiceAlternative, 0)
	c.tagIx = make(map[int]int)
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

	var options choiceOptions = choiceOptions{Tag: -1, UTag: -1}
	if len(opts) > 0 {
		options = r.tokenizeChoiceOptions(opts[0])
	}

	if r.cfg.Automatic {
		r.cfg.Explicit = true
		var tag int = len(r.alts)
		// If automatic, grab the last choiceAlternative
		// tag number and increment by one.
		if options.Tag == -1 {
			options.Tag = tag // OVERRIDE
		}
	}

	if _, dup := r.tagIx[options.Tag]; dup {
		return mkerrf("duplicate CHOICE tag ", itoa(options.Tag))
	}
	r.tagIx[options.Tag] = len(r.alts)
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

func (r Choices) byTag(t any) (calt choiceAlternative, ok bool) {
	var tag int
	switch tv := t.(type) {
	case int:
		tag = tv
	case *int:
		if tv == nil {
			return
		}
		tag = *tv
	}

	var i int
	i, ok = r.tagIx[tag]
	if !ok {
		return
	}
	calt = r.alts[i]
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
		o = r.tokenizeChoiceOptions(opts[0])
		mID = true
	}

	matchID := func(alt choiceAlternative) bool {
		return alt.Opts.Tag == o.Tag
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
		c = Choice{Value: instance, Tag: &matches[0].Opts.Tag, Explicit: matches[0].Opts.Explicit}
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

	        // note: this is an abstract example
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

func selectFieldChoice(n string, constructed any, pkt Packet, opts *Options) (alt Choice, err error) {
	// First see if the construct type exports a
	// choices method of <FieldName>Choices. If so,
	// derive our Choices instance from that.
	var choices Choices
	meth, found := getChoicesMethod(n, constructed)
	if found {
		choices = meth()
	} else {
		// No <FieldName>Choices method was discovered. But
		// before we fail, see if a ChoicesMap was included
		// in the Options payload. If so, we can forego the
		// error if we find a match.
		if opts.ChoicesMap != nil {
			var ok bool
			if choices, ok = opts.ChoicesMap[opts.Choices]; !ok {
				err = errorNoChoicesAvailable
				return
			}
		} else {
			err = errorNoChoicesAvailable
			return
		}
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
			opts.choiceTag = &extractedTag // Now opts.Tag is properly set (instead of -1).
			structTag = "choice:tag:" + itoa((*opts.choiceTag))
			candidate, err = chooseChoiceCandidateBER(pkt, tlv, choices, opts)
		}
	default:
		err = mkerr("Encoding rule not supported")
	}

	if err == nil {
		alt, err = choices.Choose(candidate, structTag)
	}

	return
}

func chooseChoiceCandidateBER(pkt Packet, tlv TLV, choices Choices, opts *Options) (candidate any, err error) {
	// First try choicesTag, if defined
	alt, ok := choices.byTag(opts.choiceTag)
	if !ok {
		// FALLBACK: Lookup the candidate alternative using opts.Tag
		if alt, ok = choices.byTag(opts.Tag()); !ok {
			return nil, mkerrf("unknown choice tag: ", itoa(opts.Tag()))
		}
	}

	// Allocate a new instance of the candidate type.
	candidateInst := reflect.New(alt.Type).Interface()

	if isPrimitive(candidateInst) {
		candidateContent := tlv.Value
		ptag := alt.Opts.Tag

		sub := pkt.Type().New(byte(ptag))
		sub.Append(pkt.Data()[1:]...)
		sub.SetOffset(pkt.Offset())
		if !opts.HasTag() {
			opts.SetTag(ptag)
		}

		tag, class := effectiveTag(ptag, 0, opts)
		if alt.Opts.Explicit {
			class |= 0x20
		}
		subTLV := pkt.Type().newTLV(class, tag, tlv.Length, tlv.Compound, candidateContent...)
		if c, ok := candidateInst.(codecRW); ok {
			err = c.read(sub, subTLV, opts)
		} else if bx, ok := createCodecForPrimitive(candidateInst); ok {
			if err = bx.read(sub, subTLV, opts); err == nil {
				reflect.ValueOf(candidateInst).Elem().
					Set(reflect.ValueOf(bx.getVal()))
			}

		} else {
			err = mkerr("Primitive has no codec")
		}
	} else {
		sub := pkt.Type().New(pkt.Data()...)
		sub.SetOffset(0)
		if _, err = sub.TLV(); err == nil {
			// IMPORTANT: Clear the tag override before decoding inner fields.
			// This allows inner decoders (for, say, ObjectIdentifier) to use
			// their natural universal tag.
			opts.tag = nil
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
	Name     string // name of choice per ASN.1 schema
	Explicit bool   // whether the alternative is EXPLICIT
	Tag,     // ASN.1 context tag
	UTag int // ASN.1 tag number
}

func (r Choices) tokenizeChoiceOptions(opts string) (options choiceOptions) {
	options.Tag, options.UTag = -1, -1
	if opts = lc(opts); hasPfx(opts, "choice:") {
		sp := split(trimPfx(opts, "choice:"), `,`)
		for _, slice := range sp {
			switch {
			case hasPfx(slice, "tag:"):
				if t, err := atoi(trimPfx(slice, "tag:")); err == nil && options.Tag == -1 {
					options.Tag = t
				}
			case slice == "explicit":
				if !r.cfg.Automatic {
					options.Explicit = true
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
