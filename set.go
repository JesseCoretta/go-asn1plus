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
	isChoice := unmarshalSetIsChoice(elemType)

	for pkt.HasMoreData() {
		var tmp reflect.Value
		if elemType.Kind() == reflect.Ptr {
			tmp = reflect.New(elemType.Elem())
		} else {
			tmp = reflect.New(elemType).Elem()
		}

		if isChoice {
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
	def choiceAlternative,
	tag int,
	payload []byte,
	payloadPK PDU,
	newOpts *Options,
	err error,
) {
	start := pkt.Offset()
	outer, err := pkt.TLV()
	if err != nil {
		return def, 0, nil, nil, nil, err
	}

	allData, hdrLen := unmarshalSetOfChoiceHeaderLength(start, pkt)
	end := start + hdrLen + outer.Length
	raw := allData[start:end]
	pkt.SetOffset(end)

	opts := clearChildOpts(parentOpts)
	reg, ok := opts.ChoicesMap[opts.Choices]
	if !ok {
		return def, 0, nil, nil, nil, errorNoChoicesAvailable
	}

	outerTag := outer.Tag
	def, found := reg.byTag(&outerTag)

	mustUnwrap := (found && def.Opts.Explicit) ||
		(!found && outer.Class != ClassUniversal && outer.Compound)

	if mustUnwrap {
		innerBytes := raw[hdrLen:]
		innerPK := pkt.Type().New(innerBytes...)
		innerPK.SetOffset(0)

		itlv, err := innerPK.TLV()
		if err != nil {
			return def, 0, nil, nil, nil, err
		}
		tag = itlv.Tag

		_, innerHdr := unmarshalSetOfChoiceHeaderLength(0, innerPK)
		payload = innerBytes[innerHdr:]
		payloadPK = innerPK

		def, found = reg.byTag(&tag)
		if !found {
			return def, tag, nil, nil, nil,
				mkerrf("no CHOICE variant for tag ", itoa(tag))
		}

	} else {
		tag = outer.Tag
		payload = raw[hdrLen:]
		payloadPK = pkt.Type().New(payload...)
		payloadPK.SetOffset(0)

		if !found {
			return def, tag, nil, nil, nil,
				mkerrf("no CHOICE variant for tag ", itoa(tag))
		}
	}

	opts.choiceTag = new(int)
	*opts.choiceTag = tag
	opts.SetTag(tag)

	return def, tag, payload, payloadPK, opts, nil
}

func setDecodeChoiceSingle(
	tmp reflect.Value,
	def choiceAlternative,
	payloadPK PDU,
	opts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {
	var dest reflect.Value
	if def.Type.Kind() == reflect.Ptr {
		dest = reflect.New(def.Type.Elem())
	} else {
		dest = reflect.New(def.Type)
	}

	childOpts := *opts
	childOpts.tag = nil
	if err := unmarshalValue(payloadPK, dest, &childOpts); err != nil {
		return tmp, mkerrf("inner decode failed: ", err.Error())
	}

	val := dest.Elem().Interface()
	var out Choice
	out.Value = val
	out.Explicit = def.Opts.Explicit
	out.SetTag(def.Opts.Tag)

	if elemType.Kind() == reflect.Ptr {
		tmp.Elem().Set(reflect.ValueOf(out))
	} else {
		tmp.Set(reflect.ValueOf(out))
	}
	return tmp, nil
}

func handleChoiceSlice(
	tmp reflect.Value,
	alt choiceAlternative,
	payload []byte,
	payloadPK PDU,
	opts *Options,
) (reflect.Value, bool, error) {
	if alt.Type.Kind() != reflect.Slice {
		return tmp, false, nil
	}
	elemT := alt.Type.Elem()
	sample := reflect.Zero(elemT).Interface()

	if _, ok := sample.(codecRW); !ok {
		if _, ok := createCodecForPrimitive(sample); !ok {
			return tmp, false, nil
		}
	}

	sliceVal := reflect.MakeSlice(alt.Type, 0, 0)
	for payloadPK.HasMoreData() {
		off := payloadPK.Offset()
		tlv2, err := payloadPK.TLV()
		if err != nil {
			return tmp, true, mkerrf("slice-element TLV: ", err.Error())
		}
		raw2 := payload[off:]
		var h2 int
		if raw2[1]&0x80 != 0 {
			h2 = 2 + int(raw2[1]&0x7F)
		} else {
			h2 = 2
		}
		total := h2 + tlv2.Length
		part := raw2[:total]

		subPK := payloadPK.Type().New(part...)
		subPK.SetOffset(0)

		childOpts := *opts
		childOpts.tag = nil

		ptr := reflect.New(elemT)
		if err := unmarshalValue(subPK, ptr, &childOpts); err != nil {
			return tmp, true, mkerrf("slice decode: ", err.Error())
		}
		sliceVal = reflect.Append(sliceVal, ptr.Elem())
		payloadPK.SetOffset(off + total)
	}

	var out Choice
	out.Value = sliceVal.Interface()
	out.Explicit = alt.Opts.Explicit
	out.SetTag(alt.Opts.Tag)

	if elemT.Kind() == reflect.Ptr {
		tmp.Elem().Set(reflect.ValueOf(out))
	} else {
		tmp.Set(reflect.ValueOf(out))
	}
	return tmp, true, nil
}

func unmarshalSetOfChoice(
	pkt PDU,
	tmp reflect.Value,
	parentOpts *Options,
	elemType reflect.Type,
) (reflect.Value, error) {
	def, _, payload, payloadPK, opts, err := setPickChoiceAlternative(pkt, parentOpts)
	if err != nil {
		return tmp, err
	}

	if out, handled, err := handleChoiceSlice(tmp, def, payload, payloadPK, opts); err != nil {
		return tmp, err
	} else if handled {
		return out, nil
	}

	return setDecodeChoiceSingle(tmp, def, payloadPK, opts, elemType)
}
