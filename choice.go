package asn1plus

import (
	"reflect"
	"sync"
)

/*
Choice implements an interface for the ASN.1 CHOICE type. Instances
of this type can be crafted using the [NewChoice] function.
*/
type Choice interface {
	// Value returns the underlying value residing
	// within the receiver instance of Choice.
	Value() any

	// Tag returns the associated Choice tag.  If
	// no tag was specified, -1 is returned.
	Tag() int

	isChoice()
}

type wrappedChoice struct {
	inner any
	tag   int // −1 means “use registry”
}

type invalidChoice struct{}

func (_ invalidChoice) isChoice()  {}
func (_ invalidChoice) Tag() int   { return -1 }
func (_ invalidChoice) Value() any { return errorNilReceiver }

func (_ wrappedChoice) isChoice()  {}
func (r wrappedChoice) Tag() int   { return r.tag }
func (r wrappedChoice) Value() any { return r.inner }

/*
NewChoice returns a new instance of [Choice], which wraps the input
value v.

The variadic int input argument allows for the occasional inclusion
of a context tag (e.g.: 3 for [3]).

Use of a context tag is required in cases where more than one instance
of a single type (e.g.: [ObjectIdentifier] resides within a registered
instance of [Choices] from which a selection is to be made.
*/
func NewChoice(v any, tag ...int) Choice {
	// NewChoice(v)        -> registry lookup (tag = −1)
	// NewChoice(v, t)     -> explicit override (tag = t)

	t := -1
	if len(tag) > 0 {
		t = tag[0]
	}
	return wrappedChoice{inner: v, tag: t}
}

var (
	choicesRegistry map[string]Choices
	chMu            sync.RWMutex
)

/*
RegisterChoices associates the input string name and [Choices]
instances within the central registry of [Choices]. Note that
case folding is not significant in the registration process,
however the input [Choices] instance MUST have a length greater
than zero (0)
*/
func RegisterChoices(name string, choices Choices) {
	if choices.Len() > 0 {
		chMu.Lock()
		defer chMu.Unlock()
		choicesRegistry[lc(name)] = choices
	}
}

/*
UnregisterChoices removes the [Choices] value bearing the input
string name from the central [Choices] registry. Note that case
folding is not significant in the matching process.
*/
func UnregisterChoices(name string) {
	chMu.Lock()
	defer chMu.Unlock()
	delete(choicesRegistry, lc(name))
}

/*
GetChoices scans the central [Choices] registry for an instance
of [Choices] associated with the input string name.  Note that
case folding is not significant in the matching process.
*/
func GetChoices(name string) (Choices, bool) {
	choices, found := choicesRegistry[lc(name)]
	return choices, found
}

/*
Choices implements a collection of ASN.1 CHOICE alternatives
for a particular definition. Instances of this type are created
using the [NewChoices] constructor.

It is not necessary to preserve an instance of [Choices] beyond
its registration in the central [Choices] registry.
*/
type Choices struct {
	auto bool
	reg  map[reflect.Type]*choiceDescriptor
}

/*
choiceDescriptor encapsulates tag, class, explicit and reflect.Type
for use in a single CHOICE selectable.
*/
type choiceDescriptor struct {
	tagToType map[int]reflect.Type
	typeToTag map[reflect.Type]int
	explicit  map[int]bool
	class     map[int]int // tag->class
}

/*
NewChoices returns an instance of [Choices] which is immediately
ready for new registrations via the [Choices.Register] method.

The variadic auto input value can be used to configure the return
[Choices] instance for automatic tagging.

Once all registrations have been made, the return instance should
be registered within the global [RegisterChoices] function so that
it can be used by any subsequent [Marshal] or [Unmarshal] calls.
It is not necessary to preserve an instance of [Choices] beyond
its registration in the central [Choices] registry.
*/
func NewChoices(auto ...bool) Choices {
	var autoTag bool
	if len(auto) > 0 {
		autoTag = auto[0]
	}
	return Choices{
		autoTag,
		make(map[reflect.Type]*choiceDescriptor),
	}
}

/*
Len returns the integer length of the receiver instance.
*/
func (r Choices) Len() int { return len(r.reg) }

/*
Register creates a registration within the receiver instance, which
associates ifacePtr, alt, class, tag and explicit for later use in
an ASN.1 CHOICE selection.
*/
func (r Choices) Register(
	ifacePtr any,
	concrete any,
	opts ...*Options,
) (err error) {

	class := ClassContextSpecific
	tag := -1
	explicit := false

	if len(opts) > 0 && opts[0] != nil {
		if opts[0].Class() != ClassUniversal {
			class = opts[0].Class()
		}
		if opts[0].HasTag() {
			tag = opts[0].Tag()
		}
		explicit = opts[0].Explicit
	}

	debugEnter(
		newLItem(ifacePtr, "interface pointer"),
		newLItem(concrete, "concrete instance"),
		newLItem(class, "choice class"),
		newLItem(tag, "choice tag"),
		newLItem(explicit, "choice explicit"))

	defer func() { debugExit(newLItem(err)) }()

	// always group alternatives under the Choice
	// interface if none was specified
	var key reflect.Type
	if ifacePtr != nil {
		key = refTypeOf(ifacePtr).Elem()
	} else if r.auto {
		key = choicePtrType
	} else {
		key = derefTypePtr(refTypeOf(concrete))
	}

	cd, ok := r.reg[key]
	if !ok {
		cd = &choiceDescriptor{
			tagToType: make(map[int]reflect.Type),
			typeToTag: make(map[reflect.Type]int),
			explicit:  make(map[int]bool),
			class:     make(map[int]int), // tag->class
		}
		r.reg[key] = cd
	}

	// Automatic tagging logic: if r.auto==true and no user‐tag supplied
	if r.auto && tag < 0 {
		maxTag := -1
		for existingTag := range cd.tagToType {
			if existingTag > maxTag {
				maxTag = existingTag
			}
		}
		tag = maxTag + 1
		explicit = true
	}

	// Prevent duplicate tag
	if _, dup := cd.tagToType[tag]; dup {
		err = choiceErrorf("duplicate tag found during registration: ", tag)
		return
	}

	// Record the alternative
	altType := derefTypePtr(refTypeOf(concrete))
	cd.tagToType[tag] = altType
	cd.typeToTag[altType] = tag
	cd.class[tag] = class
	cd.explicit[tag] = explicit

	return
}

/*
Choose returns a Boolean value indicative of a positive match between the
input value and an ASN.1 CHOICE alternative residing within the receiver
instance.

If ambiguity is encountered -- for instance two of the same type within
the receiver instance -- and no tag was specified, a value of false will
be returned implicitly.
*/
func (r Choices) Choose(value any, tag ...int) bool {
	var ok bool
	if value == nil {
		return ok
	}

	valType := derefTypePtr(refTypeOf(value))

	switch len(tag) {
	case 1:
		// tag‐driven lookup
		t := tag[0]
		var cd *choiceDescriptor
		if _, cd, ok = r.lookupDescriptorByTag(t); ok {
			expected, exists := cd.tagToType[t]
			ok = exists && expected == valType
		}

	case 0:
		// try concrete‐type lookup (more likely to be used)
		if _, _, ok = r.lookupDescriptorByConcrete(valType); !ok {
			// try interface‐implementation lookup
			for ifaceType := range r.reg {
				if ok = valType.Implements(ifaceType); ok {
					break
				}
			}
		}
	}

	return ok
}

func (r Choices) lookupDescriptorByTag(tag int) (
	ifaceType reflect.Type,
	desc *choiceDescriptor,
	ok bool,
) {
	for iface, cd := range r.reg {
		if _, exists := cd.tagToType[tag]; exists {
			ifaceType = iface
			desc = cd
			ok = true
			break
		}
	}
	return
}

func (r *Choices) lookupDescriptorByConcrete(concrete reflect.Type) (iface reflect.Type, desc *choiceDescriptor, ok bool) {
	for ifaceType, d := range r.reg {
		if _, exists := d.typeToTag[concrete]; exists {
			iface = ifaceType
			desc = d
			ok = true
			break
		}
	}
	return
}

func (r Choices) lookupDescriptorByInterface(iface reflect.Type) (desc *choiceDescriptor, ok bool) {
	desc, ok = r.reg[iface]
	return
}

func unmarshalUnwrapInterfaceChoice(sub PDU, fv reflect.Value, opts *Options) (err error) {
	if opts.Class() != 0 && fv.Kind() == reflect.Interface && opts.Choices != "" {
		if _, err = sub.TLV(); err != nil {
			// unwrap interface-based choices
			err = choiceErr{err}
		}
	}
	return
}

func marshalChoiceWrapper(
	parent any,
	pkt PDU,
	opts *Options,
	v reflect.Value,
) (err error) {
	debugEnter(newLItem(parent, "parent"), opts, v, pkt)
	defer func() { debugExit(newLItem(err)) }()

	cw := v.Interface().(Choice)
	inner := cw.Value()
	if inner == nil {
		// No value? Try to get a default
		inner = opts.Default
		debugEvent(EventChoice|EventTrace, "use registered default value")
	}
	debugEvent(EventChoice|EventTrace, newLItem(inner, "value"))

	cho, found := GetChoices(opts.Choices)
	if !found || cho.Len() == 0 {
		err = errorNoChoicesAvailable
		return
	}

	typ := pkt.Type()

	// marshal the inner TLV (UNIVERSAL
	// class) into a temp PDU
	tmp := typ.New()
	innerOpts := clearChildOpts(opts)
	innerOpts.Choices = ""
	if err = marshalValue(refValueOf(inner), tmp, innerOpts); err != nil {
		err = choiceErr{err}
		return
	}
	innerBytes := tmp.Data()

	// decide which tag, class, explicit to emit
	tag := cw.Tag()               // user override or -1
	class := ClassContextSpecific // default
	explicit := true              // always explicit for choice

	if tag < 0 {
		// no override -> look up registry by concrete type
		t := derefTypePtr(refTypeOf(inner))
		_, desc, ok := cho.lookupDescriptorByConcrete(t)
		if !ok {
			err = choiceErrorf("marshalChoiceWrapper: no alternative for ", t)
			return
		}
		tag = desc.typeToTag[t]
		class = desc.class[tag]
		explicit = desc.explicit[tag]
	}

	debugEvent(EventTrace|EventChoice,
		newLItem([]int{class, tag}, "class/tag"),
		newLItem(explicit, "explicit"))

	pkt.Append(emitHeader(class, tag, explicit))
	buf := getBuf()
	encodeLengthInto(typ, buf, len(innerBytes))
	pkt.Append(*buf...)
	putBuf(buf)
	pkt.Append(innerBytes...)

	return
}

/*
isInterfaceChoice returns a Boolean value indicative of
v being an interface that is NOT an actual Choice when
combined with a non-zero list of Choices.

A return value of true indicates that the user wants to
treat a non-Choice interface as a Choice. In this case,
use of this function is usually followed an "artificial
Choice wrapping" of the underlying interface value.
*/
func isInterfaceChoice(v reflect.Value, opts *Options) bool {
	_, is := v.Interface().(Choice)
	return !is && v.Kind() == reflect.Interface && opts.Choices != ""
}

func isChoice(v reflect.Value, opts *Options) (ok bool) {
	debugEnter(v, opts)
	defer func() { debugExit(newLItem(ok, "isChoice")) }()

	if deferImplicit(opts).Choices == "" || !v.IsValid() {
		debugEvent(EventChoice, "isChoice: empty choices or invalid value")
		return
	}

	// If it’s an interface (and NOT a concrete
	// instance), peel it one level.
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			debugEvent(EventChoice, "interface is nil")
			return
		}
		v = v.Elem()
	}

	// Only the exact Choice‐alias type is a CHOICE
	if v.Type() == choiceIfaceType {
		_, ok = v.Interface().(Choice)
	}

	return
}

func init() {
	choicesRegistry = make(map[string]Choices)
}
