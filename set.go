package asn1plus

/*
set.go contains all private functions pertaining to the
ASN.1 SET type.
*/

import (
	"bytes"
	"reflect"
	"slices"
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
func marshalSet(v reflect.Value, pkt Packet, opts *Options, depth int) (err error) {
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
			err = mkerr("marshalSet: no suitable slice field found in struct")
			return
		}
	} else if v.Kind() != reflect.Slice {
		err = mkerr("marshalSet: value is not a slice or struct containing a slice")
		return
	}

	var elements [][]byte
	for i := 0; i < v.Len() && err == nil; i++ {
		tmp := pkt.Type().New()
		subOpts := clearChildOpts(opts)

		if err = marshalValue(v.Index(i), tmp, subOpts, depth+1); err == nil {
			elements = append(elements, tmp.Data())
		}
	}

	if err != nil {
		err = mkerrf("marshalSet: error marshaling slice element: ", err.Error())
		return
	}

	if pkt.Type() == DER {
		slices.SortFunc(elements, func(a, b []byte) int {
			return bytes.Compare(a, b)
		})
	}

	bufPtr := getBuf()
	concatenated := *bufPtr
	for _, e := range elements {
		concatenated = append(concatenated, e...)
	}

	tlv := pkt.Type().newTLV(ClassUniversal, TagSet, len(concatenated), true, concatenated...)
	encoded := encodeTLV(tlv, nil)
	putBuf(bufPtr)

	pkt.Append(encoded...)
	return
}

/*
unmarshalSet returns an error following an attempt to decode a SET
from pkt into the value v. v is expected to be either a slice (e.g.
[]Integer) or a struct whose first exported field is a slice.
*/
func unmarshalSet(v reflect.Value, pkt Packet, opts *Options) (err error) {

	// Locate the underlying slice.
	if v.Kind() == reflect.Struct {
		if v, err = unmarshalSequenceAsSet(v); err != nil {
			return err
		}
	} else if v.Kind() != reflect.Slice {
		err = mkerr("unmarshalSet: target value is not a slice or struct containing a slice")
		return
	}

	// Peel off an outer SET container if present.
	cur := pkt.Offset()
	if cur < pkt.Len() {
		raw := pkt.Data()[cur]
		// Check if the next TLV is a universal SET (class 0, tag number 17).
		if (raw&0xC0) == 0 && (raw&0x1F) == 17 {
			var outerTLV TLV
			if outerTLV, err = pkt.TLV(); err != nil {
				return err
			}
			subData := outerTLV.Value
			subPkt := pkt.Type().New(subData...)
			subPkt.SetOffset(0)
			pkt = subPkt
		}
	}

	elemType := v.Type().Elem()
	var elements []reflect.Value

	var subOpts *Options
	if opts != nil {
		subOpts = clearChildOpts(opts)
	}

	isChoice := unmarshalSetIsChoice(elemType)

	for pkt.Offset() < pkt.Len() {
		var tmp reflect.Value
		if elemType.Kind() == reflect.Ptr {
			tmp = reflect.New(elemType.Elem())
		} else {
			tmp = reflect.New(elemType).Elem()
		}

		if isChoice {
			tmp, err = unmarshalSetOfChoice(pkt, tmp, subOpts, elemType)
		} else {
			if subOpts != nil {
				err = unmarshalValue(pkt, tmp, subOpts)
			} else {
				err = unmarshalValue(pkt, tmp, nil)
			}
		}
		if err != nil {
			err = mkerrf("unmarshalSet: error unmarshaling SET element: ", err.Error())
			return
		}
		elements = append(elements, tmp)
	}

	newSlice := reflect.MakeSlice(v.Type(), len(elements), len(elements))
	for i, el := range elements {
		newSlice.Index(i).Set(el)
	}

	v.Set(newSlice)
	return
}

func unmarshalSetIsChoice(elemType reflect.Type) (isChoice bool) {
	// Determine if the element type is (or points to) a Choice.
	var choiceType = reflect.TypeOf(Choice{})
	if elemType.Kind() == reflect.Ptr {
		isChoice = elemType.Elem() == choiceType
	} else {
		isChoice = elemType == choiceType
	}

	return
}

func unmarshalSequenceAsSet(v reflect.Value) (reflect.Value, error) {
	var (
		found bool
		err   error
	)

	if v.NumField() == 1 {
		field := v.Type().Field(0)
		if field.PkgPath == "" {
			f := derefValuePtr(v.Field(0))
			if f.Kind() == reflect.Slice {
				v = f
				found = true
			} else {
				err = mkerrf("unmarshalSet: struct field ", field.Name, " is not a slice; got ", f.Kind().String())
			}
		}
	}

	if !found && err == nil {
		err = mkerr("unmarshalSet: no suitable slice field found in struct")
	}

	return v, err
}

func unmarshalSetOfChoice(pkt Packet, tmp reflect.Value, subOpts *Options, elemType reflect.Type) (reflect.Value, error) {
	// Process a CHOICE element.
	startOffset := pkt.Offset()
	var err error

	var tlv TLV
	if tlv, err = pkt.TLV(); err != nil {
		return tmp, err
	}

	// Advance offset past TLV.
	pkt.SetOffset(pkt.Offset() + tlv.Length)
	// Peek at raw identifier byte.
	rawID := pkt.Data()[startOffset]
	computedTag := int(rawID) & 0x1F

	// Use tlv.Tag if valid; if tlv.Tag equals the
	// universal SET tag (17) then fallback.
	var tag int = computedTag
	if tlv.Tag != 17 {
		tag = tlv.Tag
	}

	// Record the tag in Options.
	subOpts.choiceTag = new(int)
	*subOpts.choiceTag = tag
	subOpts.SetTag(tag)
	structTag := "choice:tag:" + itoa(tag)
	var choices Choices
	var ok bool
	if subOpts.ChoicesMap != nil {
		if choices, ok = subOpts.ChoicesMap[subOpts.Choices]; !ok {
			return tmp, errorNoChoicesAvailable
		}
	} else {
		return tmp, errorNoChoicesAvailable
	}

	var candidate any
	candidate, err = chooseChoiceCandidateBER(pkt, tlv, choices, subOpts)
	if err != nil {
		return tmp, mkerrf("unmarshalSet: error selecting CHOICE: ", err.Error())
	}

	var alt Choice
	if alt, err = choices.Choose(candidate, structTag); err == nil {
		// Instead of directly passing refValueOf(alt.Value),
		// allocate a new pointer for the inner value.
		subPkt := pkt.Type().New(tlv.Value...)
		subPkt.SetOffset(0)
		innerPtr := reflect.New(reflect.TypeOf(alt.Value))
		if err = unmarshalValue(subPkt, innerPtr, subOpts); err == nil {
			// Update alt.Value from the decoded inner value.
			alt.Value = innerPtr.Elem().Interface()
			// Now, set the decoded Choice into tmp.
			if elemType.Kind() == reflect.Ptr {
				tmp.Elem().Set(reflect.ValueOf(Choice{Value: alt.Value, Tag: alt.Tag, Explicit: alt.Explicit}))
			} else {
				tmp.Set(reflect.ValueOf(Choice{Value: alt.Value, Tag: alt.Tag, Explicit: alt.Explicit}))
			}
		}
	}

	return tmp, err
}
