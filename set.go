package asn1plus

/*
set.go contains all private functions pertaining to the
ASN.1 SET type.
*/

import (
	"bytes"
	"reflect"
	"sort"
)

// isSet returns true if the target's type is a slice.
func isSet(target any, opts *Options) (set bool) {
	t := derefTypePtr(refTypeOf(target))
	if t.Kind() == reflect.Slice {
		var tag int = -1
		if opts != nil {
			tag = opts.Tag()
		}
		if t.Elem().Kind() != reflect.Uint8 {
			set = hasSfx(t.Name(), "SET") || (opts != nil && tag == TagSet)
		}
	} else if hasSfx(t.Name(), "SET") {
		set = true
	}

	return
}

/*
marshalSet returns an error following an attempt to encode a SET.
Each element is encoded with its own implicit defaults.
*/
func marshalSet(v reflect.Value, pkt Packet, opts *Options, depth int) error {
	v = derefValuePtr(v)
	if v.Kind() == reflect.Struct {
		found := false
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if field.PkgPath == "" {
				// Dereference the field if needed.
				f := derefValuePtr(v.Field(i))
				if f.Kind() == reflect.Slice {
					v = f
					found = true
					break
				}
			}
		}
		if !found {
			return mkerr("marshalSet: no suitable slice field found in struct")
		}
	} else if v.Kind() != reflect.Slice {
		return mkerr("marshalSet: value is not a slice or struct containing a slice")
	}

	var elements [][]byte
	for i := 0; i < v.Len(); i++ {
		tmp := pkt.Type().New()
		subOpts := clearChildOpts(opts)

		// DO NOT pass global options to inner SET elements.
		if err := marshalValue(v.Index(i), tmp, subOpts, depth+1); err != nil {
			return mkerrf("marshalSet: error marshaling element ", itoa(i), ": ", err.Error())
		}
		elements = append(elements, tmp.Data())
	}

	if pkt.Type() == DER {
		sort.Slice(elements, func(i, j int) bool {
			return bytes.Compare(elements[i], elements[j]) < 0
		})
	}

	// TODO: retire this
	bufPtr := getBuf()
	concatenated := *bufPtr
	for _, e := range elements {
		concatenated = append(concatenated, e...)
	}

	tlv := pkt.Type().newTLV(ClassUniversal, TagSet, len(concatenated), true, concatenated...)
	encoded := encodeTLV(tlv, nil)
	// TODO: and this.
	putBuf(bufPtr)

	pkt.Append(encoded...)
	return nil
}

/*
unmarshalSet returns an error following an attempt to decode a SET
from pkt into the value v. v is expected to be either a slice (e.g.
[]Integer) or a struct whose first exported field is a slice.
*/
func unmarshalSet(v reflect.Value, pkt Packet, opts *Options) error {
	var err error

	// NOTE: We do not call pkt.TLV() here because the outer
	// SET TLV has already been handled. The Packet contains
	// only the concatenated inner SET elements.

	v = derefValuePtr(v)
	// If v is a struct, locate its slice field.
	if v.Kind() == reflect.Struct {
		found := false
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if field.PkgPath == "" {
				f := derefValuePtr(v.Field(i))
				if f.Kind() == reflect.Slice {
					v = f
					found = true
					break
				} else {
					return mkerrf("unmarshalSet: struct field ", field.Name,
						" is not a slice; got ", f.Kind().String())
				}
			}
		}
		if !found {
			return mkerr("unmarshalSet: no suitable slice field found in struct")
		}
	} else if v.Kind() != reflect.Slice {
		return mkerr("unmarshalSet: target value is not a slice or struct containing a slice")
	}

	// v is now the slice we need to populate.
	elemType := v.Type().Elem()
	var elements []reflect.Value

	var subOpts *Options
	if opts != nil {
		subOpts = clearChildOpts(opts)
	}

	// Decode elements until no more data is available.
	// (pkt here is assumed to contain only the SET’s inner payload.)
	for pkt.Offset() < pkt.Len() {
		tmp := reflect.New(elemType).Elem()
		if subOpts != nil {
			err = unmarshalValue(pkt, tmp, subOpts)
		} else {
			err = unmarshalValue(pkt, tmp, nil)
		}

		if err != nil {
			return mkerrf("unmarshalSet: error unmarshaling SET element: ", err.Error())
		}
		elements = append(elements, tmp)
	}

	// Build a new slice of the appropriate type and assign the decoded elements.
	newSlice := reflect.MakeSlice(v.Type(), len(elements), len(elements))
	for i, el := range elements {
		newSlice.Index(i).Set(el)
	}
	v.Set(newSlice)

	return nil
}
