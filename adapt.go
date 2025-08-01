package asn1plus

/*
adapt.go contains "adapters" which effectively bind common Go types, such
as string, []byte, time.Time, et al., to ASN.1 primitives (and vice versa).
*/

import (
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
)

var (
	mu              sync.RWMutex
	adapters        = map[[2]string]adapter{} // key: {goType, tagKeyword}
	defaultAdapters = map[string][]adapter{}  // key: goType
	adaptersVer     int64
	kwFastMu        sync.RWMutex
	kwFastV         int64
	kwFast          map[string]struct{}
	listCacheMu     sync.RWMutex
	listCacheVer    int64
	listCacheData   []AdapterInfo
	kwCacheVal      atomic.Value
	rebuildKwMu     sync.Mutex
	master          = map[reflect.Type]factories{}
	aiPool          = sync.Pool{
		New: func() any { return make([]AdapterInfo, 0, 64) },
	}
)

type adapterKwCache struct {
	ver  int64
	keys []string
}

func getAiSlice() []AdapterInfo  { return aiPool.Get().([]AdapterInfo)[:0] }
func putAiSlice(s []AdapterInfo) { aiPool.Put(s[:0]) } // use with defer

/*
lookupAdapter returns an instance of adapter alongside an error, following
an attempt to retrieve a particular adapter through a keyword/type pair.
*/
func lookupAdapter(goType, kw string) (ad adapter, err error) {
	debugEvent(EventEnter|EventAdapter,
		goType, newLItem(kw, "adapter keyword"))
	defer func() {
		debugEvent(EventExit|EventAdapter, ad, err)
	}()

	var exists bool

	if kw = lc(kw); kw != "" {
		mapKey := [2]string{goType, kw} // Precompute the lookup key
		if ad, exists = adapters[mapKey]; !exists {
			err = adapterErrorf("no named adapter for ",
				goType, " with keyword ", kw)
		}
		return
	}

	var list []adapter
	if list, exists = defaultAdapters[goType]; !exists || len(list) == 0 {
		err = adapterErrorf("no default adapter for ", goType)
	} else {
		ad = chainAdapters(list)
	}

	return
}

func chainAdapters(candidates []adapter) (adapt adapter) {
	debugEvent(EventEnter|EventAdapter, candidates)
	defer func() {
		debugEvent(EventExit|EventAdapter, newLItem(adapt, "chained adapter"))
	}()

	return adapter{
		newCodec: candidates[0].newCodec,
		toGo:     candidates[0].toGo,
		fromGo: func(g any, prim Primitive, opts *Options) (err error) {
			debugEvent(EventEnter|EventAdapter, g, prim, opts)
			defer func() {
				debugEvent(EventExit|EventAdapter, newLItem(err))
			}()

			var found bool
			for i := 0; i < len(candidates) && !found; i++ {
				found = candidates[i].fromGo(g, prim, opts) == nil
			}
			if !found {
				err = adapterErrorf("none of the default adapters accepted value")
			}
			return
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
func adapterForValue(v reflect.Value, kw string) (ad adapter, ok bool) {
	debugEnter(v, kw)
	defer func() {
		debugExit(ad, newLItem(ok, "registered"))
	}()

	var f factories
	if f, ok = master[v.Type()]; ok {
		debugAdapter(newLItem(f), "adapter exact match")
		ad = buildAdapter(f, v.Interface())
		ok = true
		return
	}

	vv := derefValuePtr(v)
	if f, ok = master[vv.Type()]; ok {
		debugAdapter(newLItem(f), "adapter deref")
		ad = buildAdapter(f, vv.Interface())
		ok = true
		return
	}

	var err error
	ad, err = lookupAdapter(v.Type().String(), kw)
	ok = err == nil

	return
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

/*
adapterKeywords returns a sorted list of *all* non-empty identifiers
that have been registered through RegisterAdapter.

This function is only used internally by the Options parser, but it
reuses the public ListAdapters helper so we don’t touch the protected
maps directly.
*/
func adapterKeywords() (out []string) {
	debugEvent(EventEnter | EventAdapter)
	defer func() {
		debugEvent(EventExit|EventAdapter,
			newLItem(out, "adapter keywords"))
	}()

	cur := atomic.LoadInt64(&adaptersVer)
	debugAdapter(newLItem(int(cur), "adapters version"))

	c := kwCacheVal.Load().(adapterKwCache)
	debugEvent(EventTrace|EventAdapter,
		newLItem(c.ver, "cached kw ver"),
		newLItem(len(c.keys), "cached kw keys"))

	if c.ver == cur {
		// lock‐free load
		debugAdapter(newLItem(c.keys, "fast‐path keys"))
		return c.keys
	}

	debugAdapter(
		newLItem(c.ver, "cached kw ver"),
		newLItem(cur, "current kw version"),
		"kw cache miss, acquiring rebuildKwMu lock",
	)
	rebuildKwMu.Lock()
	defer func() {
		debugEvent(EventTrace|EventAdapter, "rebuildKwMu unlocking")
		rebuildKwMu.Unlock()
	}()

	c = kwCacheVal.Load().(adapterKwCache)
	if c.ver != cur {
		debugAdapter(
			newLItem(c.ver, "kw cache ver after lock"),
			newLItem(cur, "still rebuilding for kw version"),
		)

		debugEvent(EventTrace|EventAdapter, "building unique kw set")
		uniq := make(map[string]struct{}, 32)
		for _, ai := range ListAdapters() {
			if ai.Keyword != "" {
				uniq[ai.Keyword] = struct{}{}
			}
		}
		debugAdapter(newLItem(len(uniq), "unique kw count"))
		out = make([]string, 0, len(uniq))
		for k := range uniq {
			out = append(out, k)
		}
		debugAdapter(newLItem(len(out), "kw slice built"))
		if len(out) > 0 {
			slices.Sort(out)
			debugAdapter(newLItem(out, "slices.Sort unique kw"))
		}

		debugEvent(EventTrace|EventAdapter,
			newLItem(cur, "storing new kw version"),
			newLItem(len(out), "storing new kw"))
		kwCacheVal.Store(adapterKwCache{ver: cur, keys: out})
		debugAdapter("cache updated")
	} else {
		debugAdapter(
			"kw cache already rebuilt by peer",
			newLItem(c.ver, "kw cache version"),
			newLItem(len(c.keys), "peer‐built kw"))
		out = c.keys
	}

	return out
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
RegisterAdapter binds a pair of types—an ASN.1 [Primitive] `T` and a
Go type `GoT` to one or more textual keywords.

Once registered, [Marshal] and [Unmarshal] will automatically convert
between the two representations whenever:

  - The Go value’s dynamic type is `GoT`, **and**
  - The caller supplied the keyword via
  - A struct tag: `asn1:"<keyword>"`
  - With(Options{Identifier: "<keyword>"})
  - The keyword is the empty string "" *and* no identifier was provided (default adapter for GoT).

Typical use-cases

  - An application introduces a custom ASN.1 [Enumerated] that marshals from a first-class Go `enum` type.
  - You want `[]byte` to encode as a proprietary [OctetString] subtype under the keyword "blob".
  - You need to plug an alternative [NumericString] implementation into the pipeline without forking the library.

Generic parameters

  - T:  Any type *whose pointer* implements the [Primitive] interface (all built-in primitives already satisfy this).
  - GoT: The Go-side type you want to expose to callers; often `string`, `[]byte`, or a domain-specific struct.

Arguments

  - ctor   A function that constructs a `T` from a `GoT` and an optional list of constraints
  - asGo   Converts *T back into GoT.  Only used by [Unmarshal]
  - aliases  One or more keywords.  Use the empty string "" to mark this adapter as the fallback for the Go type

# Concurrency

RegisterAdapter is safe for concurrent use: the underlying registry is guarded by a mutex.

Example (untested)

	// Interop adapter: Go value is []int (encoding/asn1 style), and ASN.1 value is OBJECT IDENTIFIER.
	//
	//   1. constructor  ([]int -> ObjectIdentifier)
	//   2. projector    (*ObjectIdentifier -> []int)
	//   3. keywords     (no default "", user must ask for it)
	asn1plus.RegisterAdapter[asn1plus.ObjectIdentifier, []int](
	    // constructor
	    func(input []int, _ ...asn1plus.Constraint) (asn1plus.ObjectIdentifier, error) {
	        // promote each int to an interface{} so it matches
	        // NewObjectIdentifier(...any). Note that your input
	        // variables can include zero or more Constraints.
	        params := make([]any, len(arcs))
	        for i, v := range arcs {
	            params[i] = v  // or int64(v) if your ctor prefers
	        }
	        return asn1plus.NewObjectIdentifier(params...)
	    },

	    // projector
	    func(oid *asn1plus.ObjectIdentifier) []int {
	        // Split the dotted string back into integers:
	        // "1.2.840.113549" -> []int{1,2,840,113549}
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

See the bottom of adapt_on.go for a complete look at the (actively used) built-in
"prefab" adapter registrations for further insight.

Built-in "prefab" registrations can be disabled using the `-tags asn1_no_adapter_pf`
build tag.
*/
func RegisterAdapter[T any, GoT any](
	ctor func(GoT, ...Constraint) (T, error),
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
		var cs ConstraintGroup
		if cs, err = collectConstraint(opts.Constraints); err == nil {
			if goVal, ok := g.(GoT); !ok {
				err = adapterErrorf("adapter: expected ",
					refTypeOf(*new(GoT)), " got ", refTypeOf(g))
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
UnregisterAdapter removes previously registered adapters for the GoT-T binding.
  - If no aliases are passed, it deletes *all* adapters (both keyed and default) for GoT.
  - If an empty string alias ("") is passed, it clears the defaultAdapters entry.
  - Otherwise it deletes each adapters[[GoT,alias]] entry.

For instance:

	// remove only the "oid" adapter for ObjectIdentifier to string
	UnregisterAdapter[ObjectIdentifier,string]("oid")

	// remove *all* adapters for ObjectIdentifier to string
	UnregisterAdapter[ObjectIdentifier,string]()
*/
func UnregisterAdapter[T any, GoT any](aliases ...string) {
	mu.Lock()
	defer mu.Unlock()

	// Identify the Go‐type name and Primitive pointer type
	goTypeName := refTypeOf((*GoT)(nil)).Elem().String()
	primPtrType := refTypeOf((*T)(nil))

	// Build alias set; empty means “remove all for T to GoT”
	removeAll := len(aliases) == 0
	aliasSet := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		aliasSet[lc(a)] = true
	}

	// Remove matching entries from the keyed adapters map
	for key, ad := range adapters {
		if key[0] != goTypeName {
			continue
		}
		if refTypeOf(ad.newCodec()) != primPtrType {
			continue
		}
		if removeAll || aliasSet[key[1]] {
			delete(adapters, key)
		}
	}

	// Remove from defaultAdapters slice if we’re removing all
	if removeAll {
		if slice, ok := defaultAdapters[goTypeName]; ok {
			var kept []adapter
			for _, ad := range slice {
				if refTypeOf(ad.newCodec()) != primPtrType {
					kept = append(kept, ad)
				}
			}
			if len(kept) == 0 {
				delete(defaultAdapters, goTypeName)
			} else {
				defaultAdapters[goTypeName] = kept
			}
		}
	}

	atomic.AddInt64(&adaptersVer, 1)
}

func isAdapterKeyword(token string) (is bool) {
	debugEvent(EventEnter|EventAdapter, newLItem(token, "adapter keyword"))

	cur := atomic.LoadInt64(&adaptersVer)
	debugAdapter(newLItem(int(cur), "adapters version"))

	debugEvent(EventAdapter|EventTrace, "kwFastMu locking")
	kwFastMu.RLock()

	defer func() {
		debugEvent(EventAdapter|EventTrace, "kwFastMu unlocking")
		kwFastMu.RUnlock()
		debugEvent(EventExit|EventAdapter,
			newLItem(is, "found adapter keyword "+token))
	}()

	if cur == kwFastV {
		_, is = kwFast[token]
		return
	} else {
		// rebuild once
		m := make(map[string]struct{}, 64)
		for _, kw := range adapterKeywords() {
			m[kw] = struct{}{}
		}
		kwFast, kwFastV = m, cur
	}
	_, is = kwFast[token]
	return
}

/*
adapter is a private type which serves to "bind" Go types
with ASN.1 primitives (e.g.: string -> uTF8String)
*/
type adapter struct {
	newCodec func() Primitive                     // factory for temp value
	toGo     func(Primitive) any                  // codec -> plain Go
	fromGo   func(any, Primitive, *Options) error // plain Go -> codec
}

// Every concrete codec (bytesCodec[T], stringCodec[T], ...) must satisfy this.
type box interface {
	Primitive // Tag/IsPrimitive/read/write
	codecRW
	setVal(any)  // copy Go -> codec
	getVal() any // copy codec -> Go
}

type codecRW interface {
	write(PDU, *Options) (int, error)
	read(PDU, TLV, *Options) error
}

// Two factories: an empty codec for decode path, a populated one for encode.
type factories struct {
	newEmpty func() box    // produce *codec with zero value
	newWith  func(any) box // produce *codec seeded with value
}

// registerType puts BOTH the value type and its pointer into the table.
func registerType(rt reflect.Type, f factories) {
	master[rt] = f
	master[refPtrTo(rt)] = f
}

func unregisterType(rt reflect.Type) {
	delete(master, rt)
	delete(master, refPtrTo(rt))
}

func init() {
	kwCacheVal.Store(adapterKwCache{ver: 0, keys: nil})
}
