package asn1plus

import (
	"reflect"
	"sync"
)

var (
	wcMu              sync.RWMutex
	componentRegistry = make(map[string]map[string]string)
)

/*
RegisterWithComponents accepts a string name and a set of rules with
which to govern assigned values in a SEQUENCE in terms of presence or
absence.

Case folding of name is not significant in the registration process.
*/
func RegisterWithComponents(name string, rules map[string]string) {
	name = lc(name)

	debugEnter(
		newLItem(name, "component name"),
		newLItem(rules, "presence rules"))

	if rules == nil || len(rules) == 0 {
		debugInfo("nil 'WITH COMPONENTS' registration aborted for " + name)
		return
	}

	debugTrace("wcMu locking")
	wcMu.Lock()
	defer func() {
		debugTrace("wcMu unlocking")
		wcMu.Unlock()
		debugExit()
	}()

	debugTrace("registering presence rule: " + name)
	componentRegistry[name] = rules
}

/*
UnregisterWithComponents accepts a string name for use in deleting a
previous WITH COMPONENTS registration from the underlying registry.

Case folding of name is not significant in the matching process.
*/
func UnregisterWithComponents(name string) {
	name = lc(name)

	debugEnter(newLItem(name, "component name"))
	debugTrace("wcMu locking")
	wcMu.Lock()
	defer func() {
		debugTrace("wcMu unlocking")
		wcMu.Unlock()
		debugExit()
	}()

	debugTrace("deleting presence rule: " + name)
	delete(componentRegistry, name)
}

func checkWithComponents(inst any, opts *Options) (err error) {
	rt := derefTypePtr(refTypeOf(inst))

	kind := rt.Kind()
	if kind != reflect.Struct && kind != reflect.Slice && rt != choiceIfaceType {
		err = constraintViolationf("WITH COMPONENTS: expected SEQUENCE, SET or CHOICE, got '", rt, "'")
		return
	}

	rv := derefValuePtr(refValueOf(inst))

	for i := 0; i < len(opts.WithComponents); i++ {
		n := opts.WithComponents[i]
		rules, found := componentRegistry[lc(n)]
		if !found {
			err = constraintViolationf("WITH COMPONENTS: rule set '", n, "' not found")
			break
		}

		for k, v := range rules {
			val := rv.FieldByName(k)
			if val.Kind() == reflect.Invalid {
				err = constraintViolationf("WITH COMPONENTS: unknown field '", k, " specified in rule set")
				break
			}

			iface := val.Interface()
			if iface == nil && v == "PRESENT" {
				err = constraintViolationf("WITH COMPONENTS: field '", k, "' is ABSENT where PRESENT was expected")
				break
			} else if iface != nil && v == "ABSENT" {
				err = constraintViolationf("WITH COMPONENTS: field '", k, "' is PRESENT where ABSENT was expected")
				break
			}
		}

		if err == nil {
			break // this iteration passed, exit early.
		}
	}

	return
}
