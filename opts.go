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
	// If true, wrap the field in an explicit tag.
	//
	// Note that this can be enabled textually via the
	// "explicit" keyword during field parsing.
	Explicit bool

	// If true, the field is optional.
	//
	// Note that this can be enabled textually via the
	// "optional" keyword during field parsing.
	Optional bool

	// If true, the field must be nil AND a pointer type.
	Absent bool

	// If true, ignore empty values.
	//
	// Note that this can be enabled textually via the
	// "omitempty" keyword during field parsing.
	OmitEmpty bool

	// If true, encode as SET OF instead of SEQUENCE OF
	// (for collections). Mutually exclusive of Sequence.
	//
	// Note that this can be enabled textually via the
	// "set" keyword during field parsing.
	Set bool

	// If true, encode as SEQUENCE OF instead of SET OF
	// Mutually exclusive of Set.
	//
	// Note that this can be enabled textually via the
	// "sequence" keyword during field parsing.
	Sequence bool

	// If true, a SEQUENCE field is known to be of an
	// indefinite length.
	//
	// Note that this can be enabled textually via the
	// "indefinite" keyword during field parsing.
	Indefinite bool

	// If true, automatic tagging is to be applied to a SEQUENCE,
	// SET or CHOICE(s)
	//
	// Note that this can be enabled textually via the
	// "automatic" keyword during field parsing.
	Automatic bool

	// If true, store extensions -- likely those which originate
	// from so-called "future renditions" of a composite type.
	// The associated field type MUST be []TLV and MUST be the
	// first field (index 0), else an error will occur.
	//
	// Note that this can be enabled textually via the
	// "..." keyword during field parsing.
	Extension bool

	// If true, embed field SEQUENCE in-line.
	//
	// Note that this can be enabled textually via the
	// "components-of" keyword during field parsing.
	ComponentsOf bool

	// Name of key for the associated Choices of a single SEQUENCE
	// field or other context.
	//
	// Please see the RegisterChoices function for details on registering
	// Choices.
	//
	// Case is not significant.
	//
	// Note that this can be declared textually via the "choices:<name>"
	// key:value expression during field parsing.
	Choices string

	// Primitive identifier name. Only used when an adapter-based type
	// (e.g.: string, []byte, etc.) is used instead of the equivalent
	// Primitive type, and only when the adapter is used in a non-default
	// context (e.g.: "t61" vs. default "utf8").
	//
	// Valid values are: "bmp", "bit", "bool", "date", "datetime", "duration",
	// "enum", "general", "gt", "graphic", "ia5", "int", "numeric", "descriptor",
	// "oid", "octet", "printable", "real", "relativeoid", "t61", "time",
	// "timeofday", "utc", "utf8", "universal", "videotex", "visible".
	//
	// Case is not significant.
	Identifier string

	// Registered constraints to apply to the SEQUENCE field. Please see the
	// RegisterTaggedConstraint and RegisterTaggedConstraintGroup functions
	// for details on registering such elements.
	//
	// If any single slice value begins with a circumflex accent ("^"), then
	// the given constraint shall only be used during the ENCODING (Marshal)
	// phase, while a value which begins with a dollar sign ("$") shall only
	// be used during the DECODING (Unmarshal) phase. Lack of either results
	// in the constraint being used during both of these phases.
	//
	// Case is not significant.
	//
	// Note that this can be declared textually via the "constraint:<name,...>"
	// key:comma-delim-values expression during field parsing.
	Constraints []string

	// Default value to apply to the SEQUENCE field. Please see the
	// RegisterDefaultValue function for details on registration and
	// the LookupDefaultValue function for looking-up such elements.
	Default any

	tag, // if non-nil, indicates an alternative tag number.
	class *int // represents the ASN.1 class: universal, application, context-specific, or private.
	depth          int      // recursion depth
	borrowed       bool     // options came from sync.Pool?
	defaultKeyword string   // the discovered DEFAULT keyword for registered lookup
	unidentified   []string // for unidentified or superfluous keywords
}

func implicitOptions() *Options {
	o := borrowOptions()
	o.class = ptrClassUniversal
	return o
}

func defaultOptions() *Options {
	o := borrowOptions()
	o.class = ptrClassContextSpecific
	return o
}

func deferImplicit(o *Options) *Options {
	if o == nil {
		o = implicitOptions()
	}
	return o
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
		return "unstringable-value"
	}
}

func (r *Options) copyDepth(o *Options) {
	if r != nil && o != nil {
		r.depth = o.depth
	}
}

func (r *Options) incDepth() {
	if r != nil {
		r.depth++
	}
}

/*
Header returns the class/tag header byte. This method is exported
solely for debugging or troubleshooting convenience and generally
need not be executed by the end user.
*/
func (r *Options) Header() byte {
	tag, class := effectiveHeader(r.Tag(), r.Class(), r)
	return emitHeader(class, tag, r.Explicit)
}

/*
String returns the string representation of the receiver instance.
*/
func (r Options) String() string {
	var parts []string

	//addStringConfigValue(&parts, r.depth > 0, "depth:"+itoa(r.depth))
	addStringConfigValue(&parts, r.Tag() >= 0, "tag:"+itoa(r.Tag()))
	addStringConfigValue(&parts, validClass(r.Class()) && r.Class() > 0, lc(ClassNames[r.Class()]))
	addStringConfigValue(&parts, r.Explicit, "explicit")
	addStringConfigValue(&parts, r.Optional, "optional")
	addStringConfigValue(&parts, r.Absent, "absent")
	addStringConfigValue(&parts, r.Automatic, "automatic")
	addStringConfigValue(&parts, r.Set, "set")
	addStringConfigValue(&parts, r.Sequence, "sequence")

	for _, c := range r.Constraints {
		parts = append(parts, "constraint:"+c)
	}

	addStringConfigValue(&parts, r.OmitEmpty, "omitempty")

	regDef := r.defaultKeyword != ""
	addStringConfigValue(&parts, regDef, "default::"+r.defaultKeyword)

	strDef := stringifyDefault(r.Default)
	addStringConfigValue(&parts, !regDef && strDef != "", "default:"+strDef)

	addStringConfigValue(&parts, r.Extension, "...")
	addStringConfigValue(&parts, r.ComponentsOf, "components-of")

	addStringConfigValue(&parts, r.Identifier != "", lc(r.Identifier))
	addStringConfigValue(&parts, r.Choices != "", "choices:"+lc(r.Choices))

	return join(parts, ",")
}

func (r Options) defaultEquals(x any) bool { return deepEq(r.Default, x) }

/*
NewOptions returns a new instance of [Options] alongside an error
following an attempt to parse the input tag string value.

The syntax of tag is the same as [encoding/asn1], e.g.:

	asn1:"application"
	asn1:"tag:4,explicit"

This function exists solely for diagnostic purposes, and generally
need not be leveraged by the end user.
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

/*
parseOptions parses the raw tag string (e.g. `"tag:3,optional"`)
and returns a fully-populated Options value.

In hot paths, we borrow an *Options from optPool, modify it, and
finally copy the final value out so the caller still receives a
detached struct.
*/
func parseOptions(tagStr string) (opts Options, err error) {
	po := borrowOptions()
	*po = *implicitOptions()

	tagStr = trim(tagStr, `"`)
	tokens := split(tagStr, ",")

	for _, raw := range tokens {
		token := trimS(raw)

		switch {
		case hasPfx(token, "tag:"):
			numStr := trimPfx(token, "tag:")
			n, convErr := atoi(numStr)
			if convErr != nil || n < 0 {
				err = optionsErrorf("invalid tag number ", numStr)
				goto Done
			}
			po.SetTag(n)

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
		err = optionsErrorf("Unidentified or superfluous keywords found: ",
			join(po.unidentified, ` `))
	}

Done:
	out := *po
	po.Free()
	return out, err
}

func isBoolKeyword(tok string) bool  { _, ok := boolKeywords[tok]; return ok }
func isClassKeyword(tok string) bool { _, ok := classKeywords[tok]; return ok }

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
	case name == "absent":
		r.Absent = true
	case name == "...":
		r.Extension = true
	case name == "components-of":
		r.ComponentsOf = true
	case name == "set":
		r.Set = true
		r.Sequence = false
	case name == "sequence":
		r.Set = false
		r.Sequence = true
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

	if hasPfx(defStr, `:`) {
		// Double-colon found. Use defaults
		// registry instead of taking the
		// inefficient legacy path.
		defStr = trimPfx(defStr, `:`)
		defVal, err := lookupDefaultValue(defStr)
		if err == nil {
			r.defaultKeyword = defStr
			r.Default = defVal
		}
		return
	}

	// legacy path is inefficient - use of default
	// registry is highly recommended.

	switch {
	case isNumber(defStr):
		r.Default, _ = NewInteger(defStr)
	case isBool(defStr):
		r.Default, _ = pbool(defStr)
	default:
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

/*
swapAlias returns a resolved token from the input alias string.
This is only used in cases where a particular ASN.1 primitive
type is known by more than one name.
*/
func swapAlias(alias string) (token string) {
	switch alias {
	case "teletex":
		token = "t61"
	default:
		token = alias
	}

	return
}

func extractOptions(field reflect.StructField, fieldNum int, automatic bool) (opts *Options, err error) {
	if tagStr, ok := field.Tag.Lookup("asn1"); ok {
		var parsedOpts Options
		if parsedOpts, err = parseOptions(tagStr); err != nil {
			err = optionsErrorf("error parsing options for field ",
				field.Name, "(", fieldNum, "): ", err)
			return
		} else {
			opts = &parsedOpts
		}

		if !opts.HasTag() && automatic {
			if opts.Explicit {
				err = errorExplicitAutomatic
				return
			}
			opts.SetTag(fieldNum)
		}
	} else {
		opts = implicitOptions()
	}

	return
}

/*
SetTag assigns n to the receiver instance. n MUST be greater
than zero (0).

Note that this method also sets the underlying class to
[ClassContextSpecific] if, and only if, the current class is
set to [ClassUniversal].

This is a fluent method.
*/
func (r *Options) SetTag(n int) *Options {
	if n >= 0 {
		r.tag = &n
		if r.Class() == ClassUniversal {
			r.class = ptrClassContextSpecific
		}
	}
	return r
}

/*
HasTag returns a Boolean value indicative of a tag being
set within the receiver instance.
*/
func (r Options) HasTag() bool { return r.tag != nil }

/*
Tag returns the tag integer residing within the receiver
instance. If unset, -1 (invalid) is returned.
*/
func (r Options) Tag() int {
	var t int = -1 // NO valid default
	if r.tag != nil {
		t = *r.tag
	}
	return t
}

/*
SetClass assigns n to the receiver instance. n MUST be within
the bounds of [ClassUniversal] (0) and [ClassPrivate] (3).

This is a fluent method.
*/
func (r *Options) SetClass(n int) *Options {
	if ClassUniversal <= n && n <= ClassPrivate {
		r.class = &n
	}
	return r
}

/*
HasClass returns a Boolean value indicative of a class being
set within the receiver instance.
*/
func (r Options) HasClass() bool { return r.class != nil }

/*
Class returns the class integer residing within the receiver
instance. If unset, 0 ([ClassUniversal]) is returned.
*/
func (r Options) Class() int {
	var c int // default UNIVERSAL class
	if r.class != nil {
		c = *r.class
	}
	return c
}

/*
Free frees the receiver instance from memory.
*/
func (r *Options) Free() {
	if r != nil {
		*r = Options{} // zero out all fields ...
		if r.borrowed {
			optPool.Put(r) // ... AND hand it back if borrowed
		}
	}
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

/*
shortcut opts bool helpers for reduced cyclomatics
*/
func optsIsAutoTag(o *Options) bool  { return o != nil && o.Automatic }
func optsIsExplicit(o *Options) bool { return o != nil && o.Explicit }
func optsIsAbsent(o *Options) bool   { return o != nil && o.Absent }
func optsIsIndef(o *Options) bool    { return o != nil && o.Indefinite }
func optsHasChoices(o *Options) bool { return o != nil && o.Choices != "" }
func optsHasDefault(o *Options) bool { return o != nil && o.Default != nil }
func optsIsOptional(o *Options) bool { return o != nil && o.Optional }
func optsHasTag(o *Options) bool     { return o != nil && o.HasTag() }
func optsIsOmit(o *Options) bool     { return o != nil && o.OmitEmpty }

var optPool = sync.Pool{New: func() any { return &Options{} }}

func borrowOptions() (o *Options) {
	o = optPool.Get().(*Options)
	o.borrowed = true
	return
}

var (
	overrideOptions map[reflect.Type]*Options
	opMu            sync.RWMutex
)

/*
RegisterOverrideOptions associates a type with a dedicated instance of
*[Options]. Note that the input value 'typ' need not contain any values.

This is used in cases where it is not possible to supply field instructions
or a top-level *[Options] instance for use upon an instance of a type,
typically in cases where very complex structures are involved.

See also [UnregisterOverrideOptions] and [OverrideOptions].
*/
func RegisterOverrideOptions(typ any, opts *Options) {
	rtyp := refTypeOf(typ)

	debugEnter(
		newLItem(rtyp, "override type"),
		newLItem(opts, "override options"))

	if opts == nil {
		debugInfo("nil override options registration aborted for " + rtyp.String())
		return
	}

	debugTrace("opMu locking")
	opMu.Lock()
	defer func() {
		debugTrace("opMu unlocking")
		opMu.Unlock()
		debugExit()
	}()

	overrideOptions[rtyp] = opts
}

/*
UnregisterOverrideOptions deletes the type registration from
the underlying override registry in a thread safe manner.

See also [RegisterOverrideOptions] and [OverrideOptions].
*/
func UnregisterOverrideOptions(typ any) {
	rtyp := refTypeOf(typ)
	debugEnter(newLItem(rtyp, "del override type"))

	debugTrace("opMu locking")
	opMu.Lock()
	defer func() {
		debugTrace("opMu unlocking")
		opMu.Unlock()
		debugExit()
	}()

	delete(overrideOptions, rtyp)
}

/*
OverrideOptions returns the underlying map[reflect.Type]*[Options]
instance in which override *[Options] value registrations reside.

As this function does not employ locking, the return instance MUST
NOT be modified directly, but may be read without issue.

See also [RegisterOverrideOptions] and [UnregisterOverrideOptions].
*/
func OverrideOptions() map[reflect.Type]*Options { return overrideOptions }

func deferOverrideOptions(typ any, o *Options) (opts *Options) {
	o = deferImplicit(o)
	if opts, _ = lookupOverrideOptions(typ); opts == nil {
		opts = o
	} else {
		debugEvent(EventTrace, newLItem(opts,
			"override options found for "+
				refTypeOf(typ).String()))
	}
	return
}

func lookupOverrideOptions(typ any) (opts *Options, err error) {
	var rtyp reflect.Type
	if refV, is := typ.(reflect.Value); is {
		if !refV.CanInterface() {
			err = optionsErrorf("Invalid reflect.Value for options override lookup")
			return
		}
		rtyp = refV.Type()
	} else {
		rtyp = refTypeOf(typ)
	}

	debugEnter(newLItem(rtyp, "lup override type"))

	debugTrace("opMu locking")
	opMu.RLock()

	defer func() {
		debugTrace("opMu unlocking")
		opMu.RUnlock()

		debugExit(
			newLItem(opts, "override options"),
			newLItem(err))
	}()

	var exists bool
	if opts, exists = overrideOptions[rtyp]; !exists {
		err = errorOverrideOptionsNotFound(rtyp)
	}

	return
}

func init() {
	overrideOptions = make(map[reflect.Type]*Options)
}
