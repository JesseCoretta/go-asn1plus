package asn1plus

/*
dv.go contains variables and functions pertaining to the
support of any default value in a SEQUENCE field.
*/

import "sync"

var (
	defaultValues map[string]any
	dvMu          sync.RWMutex
)

/*
RegisterDefaultValue writes name and dval to the underlying default
value map in a thread safe manner.

Note that case-folding is not significant in the registration and
lookup processes.

To utilize a registered default, users must utilize the `default`
struct tag keyword using two (2) colons, e.g.:

	 type MySequence struct {
		Field0 OctetString
		Field1 PrintableString `asn1:"default::myPrintableString"`
	 }

The above would result in a lookup being conducted for "myPrintableString"
within the default registry. If found, the return is assumed to be the
default value for the field in question. If the value cannot be written
to the field type, an error will follow.

If only a single colon were used, it assumes the value should be
taken literally, which will cause errors in certain cases, or (at
the very least) will fallback to the inefficient default handler.

Existing defaults will be silently overwritten when a duplicate
registration is executed.

See also [UnregisterDefaultValue] and [DefaultValues].
*/
func RegisterDefaultValue(name string, dval any) {
	name = lc(name)

	debugEnter(
		newLItem(name, "default value reg"),
		newLItem(dval, "default value"))

	if dval == nil {
		debugInfo("nil default registration aborted for " + name)
		return
	}

	debugTrace("dvMu locking")
	dvMu.Lock()
	defer func() {
		debugTrace("dvMu unlocking")
		dvMu.Unlock()
		debugExit()
	}()

	defaultValues[name] = dval
}

/*
UnregisterDefaultValue deletes the named registration from the
underlying default registry in a thread safe manner.

Note that case-folding is not significant in the matching process.

See also [RegisterDefaultValue] and [DefaultValues].
*/
func UnregisterDefaultValue(name string) {
	name = lc(name)

	debugEnter(newLItem(name, "default value unreg"))

	debugTrace("dvMu locking")
	dvMu.Lock()
	defer func() {
		debugTrace("dvMu unlocking")
		dvMu.Unlock()
		debugExit()
	}()

	delete(defaultValues, name)
}

/*
DefaultValues returns the underlying map[string]any instance in
which default value registrations reside.

As this function does not employ locking, the return instance MUST
NOT be modified directly, but may be read without issue.

See also [RegisterDefaultValue] and [UnregisterDefaultValue].
*/
func DefaultValues() map[string]any { return defaultValues }

func lookupDefaultValue(name string) (dval any, err error) {
	name = lc(name)
	debugEnter(newLItem(name, "default value lup"))

	debugTrace("dvMu locking")
	dvMu.Lock()

	defer func() {
		debugTrace("dvMu unlocking")
		dvMu.Unlock()

		debugExit(
			newLItem(dval, "default value"),
			newLItem(err))
	}()

	var exists bool
	if dval, exists = defaultValues[name]; !exists {
		err = errorNamedDefaultNotFound(name)
	}

	return
}

func init() {
	defaultValues = make(map[string]any)
}
