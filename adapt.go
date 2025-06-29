package asn1plus

/*
adapt.go contains "adapters" which effectively bind common Go types, such
as string, []byte, time.Time, et al., to ASN.1 primitives (and vice versa).
*/

import (
	"math/big"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

/*
RegisterAdapter binds a pair of types—an ASN.1 primitive `T` and a
“plain-old” Go type `GoT`—to one or more textual keywords.

Once registered, Marshal / Unmarshal will automatically convert
between the two representations whenever:

  - the Go value’s dynamic type is `GoT`, **and**
  - the caller supplied the keyword via
  - a struct tag:       `asn1:"<keyword>"`
  - With(Options{Identifier: "<keyword>"}).
  - or the keyword is the empty string "" *and* no identifier was provided (default adapter for that Go type).

Typical use-cases

  - An application introduces a custom ASN.1 ENUMERATED that marshals from a first-class Go `enum` type.
  - You want `[]byte` to encode as a proprietary OCTET STRING subtype under the keyword "blob".
  - You need to plug an alternative NumericString implementation into the pipeline without forking the library.

Generic parameters

  - T:  Any type *whose pointer* implements the asn1plus.Primitive interface (all built-in primitives already satisfy this).
  - GoT: The Go-side type you want to expose to callers; often `string`, `[]byte`, or a domain-specific struct.

Arguments

  - ctor   A function that constructs a `T` from a `GoT` and an optional list of constraints
  - asGo   Converts *T back into GoT.  Only used by Unmarshal
  - aliases  One or more keywords.  Use the empty string "" to mark this adapter as the fallback for the Go type

# Concurrency

RegisterAdapter is safe for concurrent use: the underlying registry is guarded by a mutex.

Example (untested)

	   // Interop adapter: Go value is []int (encoding/asn1 style), and ASN.1 value is OBJECT IDENTIFIER.
	   //
	   //   1. constructor  ([]int → ObjectIdentifier)
	   //   2. projector    (*ObjectIdentifier → []int)
	   //   3. keywords     (no default "", user must ask for it)
	   asn1plus.RegisterAdapter[asn1plus.ObjectIdentifier, []int](
	       // constructor
	       func(input []int, _ ...asn1plus.Constraint[asn1plus.ObjectIdentifier]) (asn1plus.ObjectIdentifier, error) {
	           // promote each int to an interface{} so it matches
	           // NewObjectIdentifier(...any). Note that your input
		   // variables can include Constraint[ObjectIdentifier].
	           params := make([]any, len(arcs))
	           for i, v := range arcs {
	               params[i] = v  // or int64(v) if your ctor prefers
	           }
	           return asn1plus.NewObjectIdentifier(params...)
	       },

	       // projector
	       func(oid *asn1plus.ObjectIdentifier) []int {
	           // Split the dotted string back into integers:
	           // "1.2.840.113549" → []int{1,2,840,113549}
	           parts := strings.Split(oid.String(), ".")
	           out   := make([]int, len(parts))
	           for i, p := range parts {
	               n, _ := strconv.Atoi(p)     // ignore atoi error for brevity
	               out[i] = n
	           }
	           return out
	       },

	       "oid", "objectidentifier", // no ""; only used when explicitly requested
	   )

See the bottom of adapt.go for a complete look at the (actively used) built-in
adapter registrations for further insight.
*/
// adapter_register.go  (same package)

// RegisterAdapter binds a native Go type (GoT) to an ASN.1 primitive T.
// If T has already been registered in the new generic registry (master)
// we pull the factories from there; otherwise we fall back to *T Primitive.
func RegisterAdapter[T any, GoT any](
	ctor func(GoT, ...Constraint[T]) (T, error),
	asGo func(*T) GoT,
	aliases ...string,
) {
	mu.Lock()
	defer mu.Unlock()

	// Build newCodec: prefer generic factory, else legacy pointer
	var zero T
	rt := refTypeOf(zero) // concrete T (value)

	newCodec := func() (p Primitive) {
		p = any(&zero).(Primitive)   // placeholder fallback
		if f, ok := master[rt]; ok { // generic codec exists
			p = f.newEmpty()
		}
		return
	}

	// Build toGo / fromGo that work for BOTH cases
	toGo := func(p Primitive) (a any) {
		// generic path
		if bx, ok := p.(interface{ getVal() any }); ok {
			val := bx.getVal().(T)
			a = asGo(&val)
		}
		return
	}

	fromGo := func(g any, prim Primitive, opts *Options) (err error) {
		cs, err := collectConstraint[T](opts.Constraints)
		if err == nil {
			if goVal, ok := g.(GoT); !ok {
				err = mkerrf("adapter: expected ", refTypeOf(*new(GoT)).String(), " got ", refTypeOf(g).String())
			} else {
				var val T
				if val, err = ctor(goVal, cs...); err == nil {
					if bx, ok := prim.(interface{ setVal(any) }); ok {
						bx.setVal(val)
					} else {
						err = errorCodecNotFound
					}
				}
			}
		}

		return
	}

	// Store the adapter under all requested aliases
	ad := adapter{newCodec: newCodec, toGo: toGo, fromGo: fromGo}

	goTypeName := refTypeOf((*GoT)(nil)).Elem().String()
	for _, kw := range aliases {
		kw = lc(kw)
		if kw == "" {
			defaultAdapters[goTypeName] = append(defaultAdapters[goTypeName], ad)
		} else {
			adapters[[2]string{goTypeName, kw}] = ad
		}
	}
	atomic.AddInt64(&adaptersVer, 1) // cache invalidation
}

/*
AdapterInfo implements a read-only description of a single adapter mapping
currently registered in the global adapter registry.
*/
type AdapterInfo struct {
	GoType    string // concrete Go value type, e.g. "string", "[]byte", "*big.Int"
	Keyword   string // identifier that selects this adapter ("" = default)
	Primitive string // ASN.1 primitive name, e.g. "UTF8String", "Integer"
}

/*
ListAdapters returns a snapshot of every adapter that has been
registered so far—both the package-supplied defaults and any that the
application registered at run-time.

The slice is sorted first by Go type, then by keyword, so the output
is stable and easy to read in logs.

	for _, ai := range asn1plus.ListAdapters() {
	    fmt.Printf("%-12s  %-10q  %s\n", ai.GoType, ai.Keyword, ai.Primitive)
	}

The function is safe for concurrent use: it copies the internal maps
under a read lock and therefore never exposes mutable state.
*/
func ListAdapters() []AdapterInfo {
	curVer := atomic.LoadInt64(&adaptersVer)

	// fast path: cache hit
	listCacheMu.RLock()
	if curVer == listCacheVer {
		out := listCacheData
		listCacheMu.RUnlock()
		return out
	}
	listCacheMu.RUnlock()

	// slow path: rebuild once
	mu.RLock()
	tmp := getAiSlice()
	defer putAiSlice(tmp)
	out := tmp
	for k, ad := range adapters {
		out = append(out, AdapterInfo{
			GoType:    k[0],
			Keyword:   k[1],
			Primitive: refTypeOf(ad.newCodec()).Elem().String(),
		})
	}
	for goType, slice := range defaultAdapters {
		for _, ad := range slice {
			out = append(out, AdapterInfo{
				GoType:    goType,
				Keyword:   "",
				Primitive: refTypeOf(ad.newCodec()).Elem().String(),
			})
		}
	}
	mu.RUnlock()

	listCacheMu.Lock()
	listCacheVer = curVer
	listCacheData = out
	listCacheMu.Unlock()
	return out
}

/*
adapterKeywords returns a sorted list of *all* non-empty identifiers
that have been registered through RegisterAdapter.

This function is only used internally by the Options parser, but it
reuses the public ListAdapters helper so we  don’t touch the protected
maps directly.
*/
func adapterKeywords() []string {
	curVer := atomic.LoadInt64(&adaptersVer)

	// fast path
	kwCacheMu.RLock()
	if curVer == kwCacheVer {
		res := kwCacheData
		kwCacheMu.RUnlock()
		return res
	}
	kwCacheMu.RUnlock()

	// slow path: rebuild once
	uniq := make(map[string]struct{}, 32)
	for _, ai := range ListAdapters() { // ListAdapters now cheap
		if ai.Keyword != "" {
			uniq[ai.Keyword] = struct{}{}
		}
	}

	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	if len(out) > 0 {
		slices.Sort(out)
	}

	keywordSetMu.Lock()
	keywordSet = make(stringSet, len(out))
	for _, kw := range out {
		keywordSet.Add(kw) // `out` is already lower-case
	}
	keywordSetMu.Unlock()

	kwCacheMu.Lock()
	kwCacheVer = curVer
	kwCacheData = out
	kwCacheMu.Unlock()
	return out
}

type stringSet map[string]struct{}

func (s stringSet) Add(v string) { s[v] = struct{}{} }

// Not needed for now
//func (s stringSet) Has(v string) bool { _, ok := s[v]; return ok }

/*
adapter is a private type which serves to "bind" Go types
with ASN.1 primitives (e.g.: string -> uTF8String)
*/
type adapter struct {
	newCodec func() Primitive                     // factory for temp value
	toGo     func(Primitive) any                  // codec → plain Go
	fromGo   func(any, Primitive, *Options) error // plain Go → codec
}

var (
	mu                 sync.RWMutex // locker for adapters
	sortedAdapters     []AdapterInfo
	sortedKeywords     []string
	adapters           = map[[2]string]adapter{} // key: {goType, tagKeyword}
	defaultAdapters    = map[string][]adapter{}  // key: goType
	primitiveTypeNames = make(map[Primitive]string)
	adaptersVer        int64
)

var (
	kwFastMu sync.RWMutex
	kwFastV  int64
	kwFast   map[string]struct{}
)

var (
	keywordSet   stringSet
	keywordSetMu sync.RWMutex
)

// cached results + guards for ListAdapters()
var (
	listCacheMu   sync.RWMutex
	listCacheVer  int64
	listCacheData []AdapterInfo
)

// cached results + guards for adapterKeywords()
var (
	kwCacheMu   sync.RWMutex
	kwCacheVer  int64
	kwCacheData []string
)

var aiPool = sync.Pool{
	New: func() any { return make([]AdapterInfo, 0, 64) },
}

func getAiSlice() []AdapterInfo  { return aiPool.Get().([]AdapterInfo)[:0] }
func putAiSlice(s []AdapterInfo) { aiPool.Put(s[:0]) } // use with defer

func isAdapterKeyword(token string) bool {
	cur := atomic.LoadInt64(&adaptersVer)

	kwFastMu.RLock()
	if cur == kwFastV {
		_, ok := kwFast[token]
		kwFastMu.RUnlock()
		return ok
	}
	kwFastMu.RUnlock()

	kwFastMu.Lock()
	if cur != kwFastV { // rebuild once
		m := make(map[string]struct{}, 64)
		for _, kw := range adapterKeywords() {
			m[kw] = struct{}{}
		}
		kwFast, kwFastV = m, cur
	}
	_, ok := kwFast[token]
	kwFastMu.Unlock()
	return ok
}

/*
lookupAdapter returns an instance of adapter alongside an error, following
an attempt to retrieve a particular adapter through a keyword/type pair.
*/
func lookupAdapter(goType, kw string) (adapter, error) {
	kw = lc(kw) // Lowercase once

	if kw != "" {
		mapKey := [2]string{goType, kw} // Precompute the lookup key
		if ad, exists := adapters[mapKey]; exists {
			return ad, nil
		}
		return adapter{}, mkerrf("no adapter for ", goType, " with tag ", kw)
	}

	list, exists := defaultAdapters[goType]
	if !exists || len(list) == 0 {
		return adapter{}, mkerrf("no adapter for ", goType)
	}

	return chainAdapters(list), nil
}

func chainAdapters(candidates []adapter) adapter {
	return adapter{
		newCodec: candidates[0].newCodec, // any of them is fine
		toGo:     candidates[0].toGo,     // we’ll only call this after success
		fromGo: func(g any, prim Primitive, opts *Options) error {
			for _, ad := range candidates {
				if err := ad.fromGo(g, prim, opts); err == nil {
					return nil // success!
				}
			}
			return mkerr("none of the default adapters accepted value")
		},
	}
}

/*
adapterForValue returns the adapter that converts between the Go value
held in v and an ASN.1 primitive, taking the (possibly empty) tag
keyword from the struct field (e.g. "numeric", "utf8").

ok == false means no adapter is registered for that (go-type, keyword)
combination and the caller should fall back to its old code path.
*/
func adapterForValue(v reflect.Value, kw string) (adapter, bool) {
	if f, ok := master[v.Type()]; ok { // exact hit
		return buildAdapter(f, v.Interface()), true
	}
	// peel *until* we hit the value, keep the peeled value afterwards
	vv := derefValuePtr(v)
	if f, ok := master[vv.Type()]; ok {
		return buildAdapter(f, vv.Interface()), true
	}
	// legacy fallback
	name := v.Type().String()
	ad, err := lookupAdapter(name, kw)
	return ad, err == nil
}

/*
wrapOIDCtor is a special adapter "converter" to help deal with the OID constructor's
slightly different (but functionally equivalent) input signature.
*/
func wrapOIDCtor[S any](
	raw func(...any) (ObjectIdentifier, error),
	convert func(S) any,
) func(S, ...Constraint[ObjectIdentifier]) (ObjectIdentifier, error) {
	return func(s S, cs ...Constraint[ObjectIdentifier]) (ObjectIdentifier, error) {
		args := make([]any, 1+len(cs))
		args[0] = convert(s)
		for i, c := range cs {
			args[i+1] = c
		}
		return raw(args...)
	}
}

/*
wrapRelOIDCtor is a special adapter "converter" to help deal with the RelativeOID
constructor's slightly different (but functionally equivalent) input signature.
*/
func wrapRelOIDCtor[S any](
	raw func(...any) (RelativeOID, error),
	convert func(S) any,
) func(S, ...Constraint[RelativeOID]) (RelativeOID, error) {
	return func(s S, cs ...Constraint[RelativeOID]) (RelativeOID, error) {
		args := make([]any, 1+len(cs))
		args[0] = convert(s)
		for i, c := range cs {
			args[i+1] = c
		}
		return raw(args...)
	}
}

/*
wrapTemporalCtor is a special adapter "converter" to help deal with the Temporal
constraint signature for Temporal types.
*/
func wrapTemporalCtor[T any](
	raw func(any, ...Constraint[Temporal]) (T, error),
) func(time.Time, ...Constraint[T]) (T, error) {

	return func(t time.Time, cs ...Constraint[T]) (T, error) {
		tc := make([]Constraint[Temporal], len(cs))
		for i, c := range cs {
			cc := c
			tc[i] = func(x Temporal) error { return cc(x.(T)) }
		}
		return raw(t, tc...)
	}
}

// Every concrete codec (bytesCodec[T], stringCodec[T], ...) must satisfy this.
type box interface {
	Primitive // Tag/IsPrimitive/read/write
	codecRW
	setVal(any)  // copy Go → codec
	getVal() any // copy codec → Go
}

type codecRW interface {
	write(Packet, *Options) (int, error)
	read(Packet, TLV, *Options) error
}

// Two factories: an empty codec for decode path, a populated one for encode.
type factories struct {
	newEmpty func() box    // produce *codec with zero value
	newWith  func(any) box // produce *codec seeded with value
}

var master = map[reflect.Type]factories{}

// registerType puts BOTH the value type and its pointer into the table.
func registerType(rt reflect.Type, f factories) {
	master[rt] = f
	master[reflect.PtrTo(rt)] = f
}

func unregisterType(rt reflect.Type) {
	delete(master, rt)
	delete(master, reflect.PtrTo(rt))
}

func valueOf[T any](v any) T {
	switch t := v.(type) {
	case T:
		return t
	case *T:
		return *t
	default:
		panic("asn1plus: factory received incompatible type")
	}
}

func buildAdapter(f factories, seed any) adapter {
	return adapter{
		newCodec: func() Primitive { return f.newEmpty() },
		toGo:     func(p Primitive) any { return p.(box).getVal() },
		fromGo: func(g any, p Primitive, _ *Options) (_ error) {
			p.(box).setVal(seed)
			if g == nil {
				// encode path: seed is original value
				p.(box).setVal(g)
			}
			return
		},
	}
}

// parseFn converts the external string into a time.Time
// (RFC 3339, ASN.1 canonical, by layout ... .
type parseFn func(string) (time.Time, error)

// wrapTemporalStringCtor adapts a temporal constructor that wants
// (time.Time, ...Constraint[Temporal]) so it can be fed with a string.
func wrapTemporalStringCtor[T any](
	raw func(any, ...Constraint[Temporal]) (T, error),
	parse parseFn,
) func(string, ...Constraint[T]) (T, error) {

	return func(s string, cs ...Constraint[T]) (t T, err error) {
		var tm time.Time
		t = *new(T)
		if tm, err = parse(s); err == nil {
			tc := make([]Constraint[Temporal], len(cs))
			for i, c := range cs {
				cc := c
				tc[i] = func(x Temporal) error { return cc(x.(T)) }
			}
			t, err = raw(tm, tc...)
		}
		return
	}
}

func wrapRealCtor[GoT any](
	base int,
	toComponents func(GoT, int) (mant any, exp int, err error),
) func(GoT, ...Constraint[Real]) (Real, error) {

	return func(v GoT, cs ...Constraint[Real]) (Real, error) {
		m, e, err := toComponents(v, base)
		var r Real
		if err == nil {
			r, err = NewReal(m, base, e, cs...)
		}
		return r, err
	}
}

func registerStringAdapters() {
	// string <-> UTF8STring [string default!]
	RegisterAdapter[UTF8String, string](
		func(s string, cs ...Constraint[UTF8String]) (UTF8String, error) {
			return NewUTF8String(s, cs...)
		},
		func(p *UTF8String) string { return string(*p) },
		"", "utf8string", "utf8",
	)

	RegisterAdapter[NumericString, string](
		func(s string, cs ...Constraint[NumericString]) (NumericString, error) {
			return NewNumericString(s, cs...)
		},
		func(p *NumericString) string { return string(*p) },
		"numeric", "numericstring",
	)

	RegisterAdapter[PrintableString, string](
		func(s string, cs ...Constraint[PrintableString]) (PrintableString, error) {
			return NewPrintableString(s, cs...)
		},
		func(p *PrintableString) string { return string(*p) },
		"printable", "printablestring",
	)

	RegisterAdapter[VisibleString, string](
		func(s string, cs ...Constraint[VisibleString]) (VisibleString, error) {
			return NewVisibleString(s, cs...)
		},
		func(p *VisibleString) string { return string(*p) },
		"visible", "visiblestring",
	)

	RegisterAdapter[GeneralString, string](
		func(s string, cs ...Constraint[GeneralString]) (GeneralString, error) {
			return NewGeneralString(s, cs...)
		},
		func(p *GeneralString) string { return string(*p) },
		"general", "generalstring",
	)

	RegisterAdapter[T61String, string](
		func(s string, cs ...Constraint[T61String]) (T61String, error) {
			return NewT61String(s, cs...)
		},
		func(p *T61String) string { return string(*p) },
		"t61", "t61string", "teletex", "teletexstring",
	)

	RegisterAdapter[VideotexString, string](
		func(s string, cs ...Constraint[VideotexString]) (VideotexString, error) {
			return NewVideotexString(s, cs...)
		},
		func(p *VideotexString) string { return string(*p) },
		"videotex", "videotexstring",
	)

	RegisterAdapter[GraphicString, string](
		func(s string, cs ...Constraint[GraphicString]) (GraphicString, error) {
			return NewGraphicString(s, cs...)
		},
		func(p *GraphicString) string { return string(*p) },
		"graphic", "graphicstring",
	)

	RegisterAdapter[OctetString, string](
		func(s string, cs ...Constraint[OctetString]) (OctetString, error) {
			return NewOctetString(s, cs...)
		},
		func(p *OctetString) string { return string(*p) },
		"octet", "octetstring",
	)

	RegisterAdapter[IA5String, string](
		func(s string, cs ...Constraint[IA5String]) (IA5String, error) {
			return NewIA5String(s, cs...)
		},
		func(p *IA5String) string { return string(*p) },
		"ia5", "ia5string",
	)

	RegisterAdapter[BMPString, string](
		func(s string, cs ...Constraint[BMPString]) (BMPString, error) {
			return NewBMPString(s, cs...)
		},
		func(p *BMPString) string { return string(*p) },
		"bmp", "bmpstring",
	)

	RegisterAdapter[UniversalString, string](
		func(s string, cs ...Constraint[UniversalString]) (UniversalString, error) {
			return NewUniversalString(s, cs...)
		},
		func(p *UniversalString) string { return string(*p) },
		"universal", "universalstring",
	)

	RegisterAdapter[OctetString, []byte](
		func(s []byte, cs ...Constraint[OctetString]) (OctetString, error) {
			return NewOctetString(s, cs...)
		},
		func(p *OctetString) []byte { return []byte(*p) },
		"octet", "octetstring",
	)

	RegisterAdapter[BitString, []byte](
		func(s []byte, cs ...Constraint[BitString]) (BitString, error) {
			return NewBitString(s, cs...)
		},
		func(p *BitString) []byte { return []byte(p.Bytes) },
		"bit", "bitstring",
	)
}

func registerNumericalAdapters() {
	RegisterAdapter[Integer, int](
		func(n int, cs ...Constraint[Integer]) (Integer, error) {
			return NewInteger(int64(n), cs...)
		},
		func(p *Integer) int {
			if p.big {
				return int(p.Big().Int64())
			}
			return int(p.native)
		},
		"int", "integer",
	)

	RegisterAdapter[Integer, *big.Int](
		func(bi *big.Int, cs ...Constraint[Integer]) (Integer, error) {
			return NewInteger(bi, cs...)
		},
		func(p *Integer) *big.Int { return p.Big() },
		"int", "integer",
	)

	RegisterAdapter[Enumerated, int](
		func(n int, cs ...Constraint[Enumerated]) (Enumerated, error) {
			return NewEnumerated(n, cs...)
		},
		func(p *Enumerated) int { return int(*p) },
		"enum", "enumerated",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(2, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real2",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(8, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real8",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(10, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"", "real10", "real",
	)

	RegisterAdapter[Real, float64](
		wrapRealCtor(16, float64ToRealParts),
		func(p *Real) float64 { return p.Float() },
		"real16",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(2, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real2",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(8, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real8",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(10, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real10",
	)

	RegisterAdapter[Real, *big.Float](
		wrapRealCtor(16, bigFloatToRealParts),
		func(p *Real) *big.Float { return p.Big() },
		"real16",
	)
}

func registerTemporalAliasAdapters() {
	RegisterAdapter[GeneralizedTime, time.Time](
		wrapTemporalCtor[GeneralizedTime](NewGeneralizedTime),
		func(p *GeneralizedTime) time.Time { return time.Time(*p) },
		"gt", "generalizedtime", "generalized-time",
	)

	RegisterAdapter[UTCTime, time.Time](
		wrapTemporalCtor[UTCTime](NewUTCTime),
		func(p *UTCTime) time.Time { return time.Time(*p) },
		"utc", "utctime", "utc-time",
	)

	RegisterAdapter[Date, time.Time](
		wrapTemporalCtor[Date](NewDate),
		func(p *Date) time.Time { return time.Time(*p) },
		"date",
	)

	RegisterAdapter[DateTime, time.Time](
		wrapTemporalCtor[DateTime](NewDateTime),
		func(p *DateTime) time.Time { return time.Time(*p) },
		"date-time", "datetime",
	)

	RegisterAdapter[TimeOfDay, time.Time](
		wrapTemporalCtor[TimeOfDay](NewTimeOfDay),
		func(p *TimeOfDay) time.Time { return time.Time(*p) },
		"time-of-day", "timeofday",
	)

	RegisterAdapter[Time, time.Time](
		wrapTemporalCtor[Time](NewTime),
		func(p *Time) time.Time { return time.Time(*p) },
		"time",
	)

	RegisterAdapter[GeneralizedTime, string](
		wrapTemporalStringCtor[GeneralizedTime](NewGeneralizedTime, parseGeneralizedTime),
		func(p *GeneralizedTime) string { return formatGeneralizedTime(time.Time(*p)) },
		"gt", "generalizedtime",
	)

	RegisterAdapter[UTCTime, string](
		wrapTemporalStringCtor[UTCTime](NewUTCTime, parseUTCTime),
		func(p *UTCTime) string { return formatUTCTime(time.Time(*p)) },
		"utc", "utctime",
	)

	RegisterAdapter[Date, string](
		wrapTemporalStringCtor[Date](NewDate, parseDate),
		func(p *Date) string { return formatDate(time.Time(*p)) },
		"date",
	)

	RegisterAdapter[DateTime, string](
		wrapTemporalStringCtor[DateTime](NewDateTime, parseDateTime),
		func(p *DateTime) string { return formatDateTime(time.Time(*p)) },
		"date-time", "datetime",
	)

	RegisterAdapter[TimeOfDay, string](
		wrapTemporalStringCtor[TimeOfDay](NewTimeOfDay, parseTimeOfDay),
		func(p *TimeOfDay) string { return formatTimeOfDay(time.Time(*p)) },
		"time-of-day", "timeofday",
	)

	RegisterAdapter[Time, string](
		wrapTemporalStringCtor[Time](NewTime, parseTime),
		func(p *Time) string { return formatTime(time.Time(*p)) },
		"time",
	)
}

func registerMiscAdapters() {
	RegisterAdapter[Duration, string](
		func(s string, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(s, cs...)
		},
		func(p *Duration) string { return p.String() },
		"duration",
	)

	RegisterAdapter[Duration, time.Duration](
		func(td time.Duration, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(td, cs...)
		},
		func(p *Duration) time.Duration { return p.Duration() },
		"", "duration",
	)

	RegisterAdapter[Duration, int64](
		func(td int64, cs ...Constraint[Duration]) (Duration, error) {
			return NewDuration(time.Duration(td), cs...)
		},
		func(p *Duration) int64 { return int64(p.Duration()) },
		"duration",
	)

	// string <-> ObjectIdentifier. Note that we perform special
	// "wrapping" here to account for a slightly different input
	// signature on part of the ObjectIdentifier constructor.
	RegisterAdapter[ObjectIdentifier, string](
		wrapOIDCtor(NewObjectIdentifier, func(s string) any { return s }),
		func(p *ObjectIdentifier) string { return p.String() },
		"", "oid", "objectidentifier", "object-identifier",
	)

	// ditto for RelativeOID
	RegisterAdapter[RelativeOID, string](
		wrapRelOIDCtor(NewRelativeOID, func(s string) any { return s }),
		func(p *RelativeOID) string { return p.String() },
		"relativeoid", "relative-oid", "reloid",
	)

	RegisterAdapter[ObjectDescriptor, string](
		func(s string, cs ...Constraint[ObjectDescriptor]) (ObjectDescriptor, error) {
			return NewObjectDescriptor(s, cs...)
		},
		func(p *ObjectDescriptor) string { return string(*p) },
		"descriptor", "objectdescriptor", "object-descriptor",
	)

	RegisterAdapter[Boolean, bool](
		func(b bool, cs ...Constraint[Boolean]) (Boolean, error) {
			return NewBoolean(b, cs...)
		},
		func(p *Boolean) bool { return bool(*p) },
		"", "boolean", "bool",
	)
}

/*
init pre-loads adapters most likely to be used by the
end-user. This collection will likely grow over time.
*/
func init() {
	registerStringAdapters()
	registerNumericalAdapters()
	registerTemporalAliasAdapters()
	registerMiscAdapters()
}
