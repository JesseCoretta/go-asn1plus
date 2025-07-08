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
func marshalSet(v reflect.Value, pkt PDU, opts *Options) (err error) {
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

		subOpts.incDepth()
		if err = marshalValue(v.Index(i), tmp, subOpts); err == nil {
			elements = append(elements, tmp.Data())
		}
	}

	if err != nil {
		err = mkerrf("marshalSet: error marshaling slice element: ", err.Error())
		return
	}

	if pkt.Type().canonicalOrdering() {
		slices.SortFunc(elements, func(a, b []byte) int { return bytes.Compare(a, b) })
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
func unmarshalSet(v reflect.Value, pkt PDU, opts *Options) (err error) {

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

	subOpts := clearChildOpts(opts)
	isCh := isChoice(v, opts)
	//isChoice := unmarshalSetIsChoice(elemType)

	for pkt.HasMoreData() {
		var tmp reflect.Value
		if elemType.Kind() == reflect.Ptr {
			tmp = refNew(elemType.Elem())
		} else {
			tmp = refNew(elemType).Elem()
		}

		if isCh {
			tmp, err = unmarshalSetOfChoice(pkt, tmp, subOpts, elemType)
		} else {
			err = unmarshalValue(pkt, tmp, subOpts)
		}
		if err != nil {
			err = mkerrf("unmarshalSet: error unmarshaling SET element: ", err.Error())
			return
		}
		elements = append(elements, tmp)
	}

	newSlice := refMkSl(v.Type(), len(elements), len(elements))
	for i, el := range elements {
		newSlice.Index(i).Set(el)
	}

	v.Set(newSlice)
	return
}

func unmarshalSetIsChoice(elemType reflect.Type) (isChoice bool) {
	// Determine if the element type is (or points to) a Choice.
	var choiceType = refTypeOf(Choice(nil))
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

func unmarshalSetOfChoiceHeaderLength(start int, pkt PDU) (data []byte, headerLen int) {
	// Compute headerLen = identifier + length octets
	data = pkt.Data()
	if data[start+1]&0x80 != 0 {
		headerLen = 2 + int(data[start+1]&0x7F)
	} else {
		headerLen = 2
	}

	return
}

func unmarshalSetOfChoiceGetTag(tlv TLV, fullWrapper []byte) (tag int) {
	tag = int(fullWrapper[0]) & 0x1F
	if tlv.Tag != 17 { // override if non‐universal SET
		tag = tlv.Tag
	}

	return
}

func setPickChoiceAlternative(
	pkt PDU,
	parentOpts *Options,
) (
	tag int,
	payload []byte,
	payloadPK PDU,
	childOpts *Options,
	err error,
) {
	// 1) If the next TLV is a universal SET, strip it and recurse
	if tlv, pe := pkt.PeekTLV(); pe == nil &&
		tlv.Class == ClassUniversal && tlv.Tag == TagSet {
		// consume the SET tag
		if _, err = pkt.TLV(); err != nil {
			return
		}
		// recurse into its contents
		sub := pkt.Type().New(tlv.Value...)
		sub.SetOffset(0)
		return setPickChoiceAlternative(sub, parentOpts)
	}

	// 2) Consume the context-specific wrapper TLV ([n] EXPLICIT)
	outer, err := pkt.TLV()
	if err != nil {
		return
	}
	pkt.SetOffset(pkt.Offset() + len(outer.Value))

	// 3) Clone parent opts but keep the registry name
	childOpts = clearChildOpts(parentOpts)
	childOpts.Choices = parentOpts.Choices

	// 4) outer.Value already contains the full inner TLV
	//    (universal tag + length + bytes), so just reuse it
	payload = outer.Value

	// 5) The CHOICE selector is the wrapper’s tag number
	tag = outer.Tag

	// 6) Build a PDU over payload so unmarshalValue sees a valid TLV
	payloadPK = pkt.Type().New(payload...)
	payloadPK.SetOffset(0)

	return
}

func unmarshalSetOfChoice(
	pkt PDU,
	tmp reflect.Value,
	parentOpts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {

	// pull out the tag, payload PK and child opts
	tag, _, payloadPK, opts, err := setPickChoiceAlternative(pkt, parentOpts)
	if err != nil {
		return tmp, err
	}

	// decode a single choice element:
	return setDecodeChoiceSingle(tmp, tag, payloadPK, opts, elemType)
}

// 2) new setDecodeChoiceSingle
func setDecodeChoiceSingle(
	tmp reflect.Value,
	tag int,
	payloadPK PDU,
	opts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {
	// lookup registry for this SET’s CHOICE wrapper
	choices, ok := GetChoices(opts.Choices)
	if !ok || choices.Len() == 0 {
		return tmp, mkerr("no CHOICE registry for SET element")
	}
	choiceIface := refTypeOf((*Choice)(nil)).Elem()
	cd, ok := choices.lookupDescriptorByInterface(choiceIface)
	if !ok {
		return tmp, mkerr("no CHOICE registry for SET element")
	}

	// find the concrete Go type for this tag
	altT, ok := cd.tagToType[tag]
	if !ok {
		return tmp, mkerrf("no CHOICE variant for tag ", itoa(tag))
	}

	// allocate and unmarshal inner value
	destPtr := reflect.New(altT)
	childOpts := *opts
	childOpts.tag = nil

	if err := unmarshalValue(payloadPK, destPtr.Elem(), &childOpts); err != nil {
		return tmp, mkerrf("inner decode failed: ", err.Error())
	}

	// wrap in the new Choice alias
	outChoice := NewChoice(destPtr.Elem().Interface())

	// store into the tmp slot
	if elemType.Kind() == reflect.Ptr {
		tmp.Elem().Set(refValueOf(outChoice))
	} else {
		tmp.Set(refValueOf(outChoice))
	}
	return tmp, nil
}
