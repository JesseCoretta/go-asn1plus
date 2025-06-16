package asn1plus

/*
opts.go contains all types and methods pertaining to the
custom Options type, which serves to deliver instructions
to the encoding/decoding process through use of struct
tags OR manual delivery of an Options instance.
*/

import "reflect"

/*
Options implements a simple encapsulator for encoding options. Instances
of this type serve two purposes.

  - Allow the user to specify top-level encoding options (e.g.: encode a SEQUENCE with [ClassApplication] as opposed to [ClassUniversal]
  - Simplify package internals by having a portable storage type for parsed struct field instructions which bear the "asn1:" tag prefix
*/
type Options struct {
	Explicit    bool     // if true, wrap the field in an explicit tag
	Optional    bool     // if true, the field is optional
	OmitEmpty   bool     // whether to ignore empty slice values
	Set         bool     // if true, encode as SET instead of SEQUENCE (for collections)
	Indefinite  bool     // whether a field is known to be of an indefinite length
	tag         *int     // if non-nil, indicates an alternative tag number.
	class       *int     // represents the ASN.1 class: universal, application, context-specific, or private.
	Identifier  string   // "ia5", "numeric", "utf8" etc. (for string fields)
	Constraints []string // references to registered Constraint/ConstraintGroup instances
	Default     any      // default value

	choiceTag    *int     // tag for choice selection, if provided
	unidentified []string // for unidentified or superfluous keywords, mostly for maintainer troubleshooting
}

// defaultOptions returns default options (e.g., no explicit tagging, context-specific for tagged fields)
func defaultOptions() Options {
	// For tagged fields we typically default to context-specific unless overridden.
	class := ClassContextSpecific
	return Options{
		class: &class, // by default, a "tag:x" implies context-specific.
	}
}

func implicitOptions() Options {
	opts := defaultOptions()
	opts.SetClass(ClassUniversal)
	return opts
}

// add appends val to dst if cond is true.
func addStringConfigValue(dst *[]string, cond bool, val string) {
	if cond {
		*dst = append(*dst, val)
	}
}

// stringifyDefault converts r.Default into its tag-ready form.
func stringifyDefault(d any) string {
	switch v := d.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return bool2str(v)
	case Integer:
		return v.String()
	default:
		return "unidentified-value"
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r Options) String() string {
	var parts []string

	addStringConfigValue(&parts, r.Tag() >= 0, "tag:"+itoa(r.Tag()))
	addStringConfigValue(&parts, validClass(r.Class()) && r.Class() > 0, lc(ClassNames[r.Class()]))
	if r.choiceTag != nil {
		addStringConfigValue(&parts, true, "choice-tag:"+itoa(*r.choiceTag))
	}
	addStringConfigValue(&parts, r.Explicit, "explicit")
	addStringConfigValue(&parts, r.Optional, "optional")
	addStringConfigValue(&parts, r.Set, "set")

	// constraints (leave the single loop ‑ counts as one branch)
	for _, c := range r.Constraints {
		parts = append(parts, "constraint:"+c)
	}

	addStringConfigValue(&parts, r.OmitEmpty, "omitempty")

	if def := stringifyDefault(r.Default); def != "" {
		parts = append(parts, def)
	}

	addStringConfigValue(&parts, r.Identifier != "", lc(r.Identifier))

	return join(parts, ",")
}

/*
NewOptions returns a new instance of [Options] alongside an error
following an attempt to parse the input tag string value.

The syntax of tag is the same as [encoding/asn1], e.g.:

	asn1:"application"
	asn1:"tag:4,explicit"
*/
func NewOptions(tag string) (Options, error) {
	var (
		opts Options
		err  error
	)

	if tag = trimS(lc(tag)); hasPfx(tag, `asn1:`) {
		tag = trimS(tag[5:])
	}

	if len(tag) == 0 {
		err = errorEmptyASN1Parameters
	} else {
		opts, err = parseOptions(tag)
	}

	return opts, err
}

func parseOptions(tagStr string) (opts Options, err error) {
	opts = implicitOptions()
	tagStr = trim(tagStr, `"`)
	tokens := split(tagStr, ",")

	for _, token := range tokens {
		token = trimS(token)
		switch {
		case hasPfx(token, "tag:"):
			numStr := trimPfx(token, "tag:")
			var tag int
			if tag, err = atoi(numStr); err != nil || tag < 0 {
				err = mkerr("invalid tag number " + numStr)
				return opts, err
			}
			opts.SetTag(tag)
			// If a tag is provided and no class keyword is present,
			// use context-specific instead of universal. This may be
			// overridden.
			opts.SetClass(ClassContextSpecific)
		case token == "explicit":
			opts.Explicit = true
		case token == "optional":
			opts.Optional = true
		case token == "omitempty":
			opts.OmitEmpty = true
		case token == "set":
			opts.Set = true
		case hasPfx(token, "constraint:"):
			opts.Constraints = append(opts.Constraints, trimPfx(token, "constraint:"))
		case token == "indefinite":
			opts.Indefinite = true
		case hasPfx(token, "default:"):
			opts.parseOptionDefault(token)
		default:
			if isClass := opts.writeClassToken(token); !isClass {
				opts.parseOptionKeyword(token)
			}
		}
	}

	if len(opts.unidentified) > 0 {
		err = mkerr("Unidentified or superfluous keywords found: " + join(opts.unidentified, ` `))
	}

	return opts, err
}

func (r *Options) writeClassToken(name string) (written bool) {
	// NOTE: universal NOT listed because the "universal"
	// token is NOT related to ClassUniversal.
	switch {
	case name == "application":
		r.SetClass(ClassApplication)
		written = true
	case name == "context-specific" || name == "context specific":
		r.SetClass(ClassContextSpecific)
		written = true
	case name == "private":
		r.SetClass(ClassPrivate)
		written = true
	}

	return
}

func (r *Options) parseOptionDefault(token string) {
	if r.Default != nil {
		// Don't re-write duplicate instances
		// of "default:...".
		return
	}

	defStr := trimPfx(token, "default:")
	switch {
	case isNumber(defStr):
		r.Default, _ = NewInteger(defStr)
	case isBool(defStr):
		r.Default, _ = pbool(defStr)
	default:
		// TODO : string fall-back is too broad.
		// Add other cases to reduce ineffective
		// use of string.
		r.Default = defStr
	}
}

func (r *Options) parseOptionKeyword(token string) {
	// Assume unidentified tag value is a string encoding label,
	// but only set it once.
	if strInSlice(token, adapterKeywords()) {
		if r.Identifier == "" {
			r.Identifier = swapAlias(token)
		} else {
			r.unidentified = append(r.unidentified, token)
		}
	} else {
		r.unidentified = append(r.unidentified, token)
	}
}

func swapAlias(alias string) (token string) {
	switch alias {
	case "teletex":
		token = "t61"
	default:
		token = alias
	}

	return
}

func extractOptions(field reflect.StructField) (opts Options, err error) {
	if tagStr, ok := field.Tag.Lookup("asn1"); ok {
		var parsedOpts Options
		if parsedOpts, err = parseOptions(tagStr); err != nil {
			err = mkerr("Marshal: error parsing tag for field " + field.Name + ": " + err.Error())
		} else {
			opts = parsedOpts
		}
	} else {
		opts = implicitOptions()
	}

	return
}

func headerOpts(tlv TLV) Options {
	opts := Options{}
	opts.SetTag(tlv.Tag)
	opts.SetClass(tlv.Class)
	return opts
}

func (r *Options) SetTag(n int) {
	if n >= 0 {
		r.tag = &n
	}
}
func (r Options) HasTag() bool { return r.tag != nil }
func (r Options) Tag() int {
	if r.tag != nil {
		return *r.tag
	}
	return -1 // NO valid default
}

func (r *Options) SetClass(n int) {
	if n >= 0 {
		r.class = &n
	}
}

func (r Options) HasClass() bool { return r.class != nil }
func (r Options) Class() int {
	if r.class != nil {
		return *r.class
	}
	return 0 // UNIVERSAL default
}
