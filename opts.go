package asn1plus

/*
opts.go contains all types and methods pertaining to the
custom Options type, which serves to deliver instructions
to the encoding/decoding process through use of struct
tags OR manual delivery of an Options instance.
*/

import (
	"reflect"
	"sync"
)

/*
Options implements a simple encapsulator for encoding options. Instances
of this type serve two purposes.

  - Allow the user to specify top-level encoding options (e.g.: encode a SEQUENCE with [ClassApplication] as opposed to [ClassUniversal]
  - Simplify package internals by having a portable storage type for parsed struct field instructions which bear the "asn1:" tag prefix
*/
type Options struct {
	Explicit    bool               // if true, wrap the field in an explicit tag
	Optional    bool               // if true, the field is optional
	OmitEmpty   bool               // whether to ignore empty slice values
	Set         bool               // if true, encode as SET instead of SEQUENCE (for collections)
	Indefinite  bool               // whether a field is known to be of an indefinite length
	Automatic   bool               // whether automatic tagging is to be applied to a SEQUENCE, SET or CHOICE(s)
	Choices     string             // Name of ChoicesMap key for the associated Choices of a single SEQUENCE field
	Identifier  string             // "ia5", "numeric", "utf8" etc. (for string fields)
	Constraints []string           // references to registered Constraint/ConstraintGroup instances
	Default     any                // default value
	ChoicesMap  map[string]Choices // map of Choices for any number of Choice fields (maps to tag "choices:<name>")

	tag, // if non-nil, indicates an alternative tag number.
	class, // represents the ASN.1 class: universal, application, context-specific, or private.
	choiceTag *int // tag for choice selection, if provided
	unidentified []string // for unidentified or superfluous keywords
}

// immutable template copied by value.
var ctxspec = ClassContextSpecific
var defaultOptionsTemplate = Options{
	class: &ctxspec, // “tag:x” -> context-specific unless overridden
}

/*
defaultOptions returns default options (e.g., no explicit
tagging, context-specific for tagged fields)
*/
func defaultOptions() Options { return defaultOptionsTemplate }

/*
implicitOptions returns an instance of Options identical to
that returned by defaultOptions, except with the class replaced
with ClassUniversal.
*/
func implicitOptions() Options {
	opts := defaultOptions()
	opts.SetClass(ClassUniversal)
	return opts
}

func addStringConfigValue(dst *[]string, cond bool, val string) {
	if cond {
		*dst = append(*dst, val)
	}
}

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
	addStringConfigValue(&parts, r.Automatic, "automatic")
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
	addStringConfigValue(&parts, r.Choices != "", lc(r.Choices))

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

// parseOptions parses the raw tag string (e.g. `"tag:3,optional"`)
// and returns a fully-populated Options value.
//
// In hot paths we borrow an *Options from optPool, work on it, then copy
// the final value out so the caller still receives a detached struct.
func parseOptions(tagStr string) (opts Options, err error) {
	po := borrowOptions()   // ← pooled working object
	*po = implicitOptions() // start from defaults

	tagStr = trim(tagStr, `"`)
	tokens := split(tagStr, ",")

	for _, raw := range tokens {
		token := trimS(raw)

		switch {
		case hasPfx(token, "tag:"):
			numStr := trimPfx(token, "tag:")
			n, convErr := atoi(numStr)
			if convErr != nil || n < 0 {
				err = mkerrf("invalid tag number ", numStr)
				goto Done
			}
			po.SetTag(n)
			po.SetClass(ClassContextSpecific)

		case isBoolKeyword(token):
			po.setBool(token)

		case hasPfx(token, "constraint:"):
			po.Constraints = append(po.Constraints,
				trimPfx(token, "constraint:"))

		case hasPfx(token, "choices:"):
			po.Choices = trimPfx(token, "choices:")

		case hasPfx(token, "default:"):
			po.parseOptionDefault(token)

		case isClassKeyword(token):
			po.writeClassToken(token)

		default:
			po.parseOptionKeyword(token)
		}
	}

	if len(po.unidentified) > 0 {
		err = mkerrf("Unidentified or superfluous keywords found: ",
			join(po.unidentified, ` `))
	}

Done:
	opts = *po         // detach result from pooled object
	releaseOptions(po) // ALWAYS return to pool
	return
}

func isBoolKeyword(tok string) bool  { _, ok := boolKeywords[tok]; return ok }
func isClassKeyword(tok string) bool { _, ok := classKeywords[tok]; return ok }

var boolKeywords = map[string]struct{}{
	"explicit":   {},
	"optional":   {},
	"automatic":  {},
	"set":        {},
	"omitempty":  {},
	"indefinite": {},
}

var classKeywords = map[string]struct{}{
	"application":      {},
	"context-specific": {},
	"context specific": {},
	"private":          {},
}

func (r *Options) setBool(name string) {
	switch {
	case name == "explicit":
		r.Explicit = true
	case name == "automatic":
		r.Automatic = true
	case name == "omitempty":
		r.OmitEmpty = true
	case name == "optional":
		r.Optional = true
	case name == "set":
		r.Set = true
	case name == "indefinite":
		r.Indefinite = true
	}
}

func (r *Options) writeClassToken(name string) (written bool) {
	// NOTE: universal NOT listed because the "universal"
	// token is NOT related to ClassUniversal, rather it
	// relates to the ASN.1 UNIVERSAL STRING type.
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
	if isAdapterKeyword(token) {
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

func extractOptions(field reflect.StructField, fieldNum int, automatic bool) (opts Options, err error) {
	if tagStr, ok := field.Tag.Lookup("asn1"); ok {
		var parsedOpts Options
		if parsedOpts, err = parseOptions(tagStr); err != nil {
			err = mkerrf("Marshal: error parsing tag for field ", field.Name,
				"(", itoa(fieldNum), "): ", err.Error())
		} else {
			opts = parsedOpts
		}

		if !opts.HasTag() && automatic {
			if opts.Explicit {
				err = mkerr("EXPLICIT and AUTOMATIC are mutually exclusive")
				return
			}
			if opts.Class() == ClassUniversal {
				// UNLESS the user chose to override
				// the default class, here we impose
				// CONTEXT SPECIFIC (class 2).
				opts.SetClass(ClassContextSpecific)
			}
			opts.SetTag(fieldNum)
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

func clearChildOpts(o *Options) (c *Options) {
	if o != nil {
		d := *o
		c = &d

		// remove per-field overrides
		c.tag = nil
		c.class = nil
		c.Explicit = false
	}

	return
}

var optPool = sync.Pool{
	New: func() any { return &Options{} }, // zero-value Options
}

func borrowOptions() *Options { return optPool.Get().(*Options) }
func releaseOptions(o *Options) {
	*o = Options{} // zero all fields
	optPool.Put(o)
}
