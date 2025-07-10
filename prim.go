package asn1plus

/*
prim.go contains all types and methods pertaining to the general
implementation of ASN.1 primitives for this package.
*/

import "reflect"

/*
Primitive encompasses all ASN.1 primitive types:

  - [BitString]
  - [BMPString]
  - [Boolean]
  - [Date]
  - [DateTime]
  - [Duration]
  - [Enumerated]
  - [GeneralString]
  - [GeneralizedTime]
  - [GraphicString]
  - [IA5String]
  - [Integer]
  - [NumericString]
  - [ObjectDescriptor]
  - [ObjectIdentifier]
  - [OctetString]
  - [PrintableString]
  - [Real]
  - [RelativeOID]
  - [T61String]
  - [Time]
  - [TimeOfDay]
  - [UTCTime]
  - [UTF8String]
  - [UniversalString]
  - [VideotexString]
  - [VisibleString]

Custom types defined against any of the above types MUST implement this
interface.

For instance:

	type MyString BMPString
	func (r MyString) Tag() int { return theAppropriateTag }
	func (r MyString) String() string { return stringRepresentation }
	func (r MyString) IsPrimitive() bool { return true } // always return true

Additionally, they must be registered with the appropriate alias registration
function prior to use with any codec.
*/
type Primitive interface {
	Tag() int
	String() string
	IsPrimitive() bool
}

func primitiveCheckExplicitRead(tag int, pkt PDU, tlv TLV, opts *Options) (data []byte, err error) {
	if tlv.Class != opts.Class() || tlv.Tag != opts.Tag() || !tlv.Compound {
		err = mkerrf("Invalid explicit ", TagNames[tag], " header in ",
			pkt.Type().String(), " packet; received TLV: ", tlv.String())
		return
	}
	if len(pkt.Data()) < 2 {
		err = mkerr("Truncated explicit TLV header")
		return
	}

	// When an explicit wrapper is used, we assume its value holds the
	// complete encoding of the inner TLV. Here we re‑parse that inner TLV
	// and return its “trimmed” value.
	innerPkt := pkt.Type().New(tlv.Value...)
	innerPkt.Append(tlv.Value...)
	innerPkt.SetOffset(0)

	var innerTLV TLV
	if innerTLV, err = innerPkt.TLV(); err == nil {
		// Instead of returning the entire innerTLV.Value(),
		// we rely on its declared length.
		data = innerTLV.Value
		if full := innerTLV.Value; len(full) > innerTLV.Length {
			data = full[:innerTLV.Length]
		}
	}
	return
}

func primitiveCheckImplicitRead(tag int, pkt PDU, tlv TLV, opts *Options) (data []byte, err error) {

	overlay := opts.HasTag() || opts.HasClass()

	if overlay {
		if opts.HasClass() && tlv.Class != opts.Class() {
			return nil, mkerr("Class mismatch for implicit tag")
		}
		if opts.HasTag() && tlv.Tag != opts.Tag() {
			return nil, mkerr("Tag mismatch for implicit tag")
		}
		// no constructed check: implicit may keep compound bit unchanged
	} else {
		/* no overlay: expect universal header */
		if tlv.Class != ClassUniversal || tlv.Tag != tag || tlv.Compound {
			return nil, mkerrf("Invalid ", TagNames[tag], " header in ",
				pkt.Type().String(), " packet; received TLV: ", tlv.String())
		}
	}

	full := tlv.Value
	if tlv.Length >= 0 && len(full) > tlv.Length {
		full = full[:tlv.Length]
	}
	return full, nil
}

func primitiveCheckRead(tag int, pkt PDU, tlv TLV, opts *Options) (data []byte, err error) {
	if tlv.Length < 0 || (opts != nil && opts.Indefinite) {
		return nil, mkerr("prohibited: indefinite length on primitive")
	}

	canBeEmpty := tag == TagOctetString || tag == TagNull

	if data, err = primitiveCheckReadOverride(tag, pkt, tlv, opts); err == nil {
		// Chop the indefinite 0x00 0x00 markers IF we're
		// in INDEFINITE mode AND if PDU type is BER
		// WITH a length of 0x80.
		//
		// TODO: revisit this approach.
		if pkt.Type().allowsIndefinite() && pkt.Data()[1] == 0x80 {
			if data[len(data)-1] == 0x00 &&
				data[len(data)-2] == 0x00 {
				data = data[:len(data)-2]
			}
		}
	}

	if len(data) == 0 && !canBeEmpty {
		err = mkerrf("Empty ", TagNames[tag], " content in ",
			pkt.Type().String(), " PDU")
	}

	return
}

func primitiveCheckReadOverride(tag int, pkt PDU, tlv TLV, opts *Options) (data []byte, err error) {
	// If a tagging override was provided, handle it.
	if opts != nil && opts.HasTag() {
		if opts.Explicit {
			data, err = primitiveCheckExplicitRead(tag, pkt, tlv, opts)
		} else {
			// Implicit tagging: the TLV itself was retagged.
			data, err = primitiveCheckImplicitRead(tag, pkt, tlv, opts)
		}
	} else {
		// No tagging override: treat as UNIVERSAL.
		if tlv.Class != ClassUniversal || tlv.Tag != tag || tlv.Compound {
			err = mkerrf("Invalid ", TagNames[tag], " header in ",
				pkt.Type().String(), " packet; received TLV: ", tlv.String())
			return
		}

		if len(pkt.Data()) < 2 {
			err = mkerr("Truncated TLV header")
		} else {
			if full := tlv.Value; len(full) > tlv.Length && tlv.Length != -1 {
				data = full[:tlv.Length]
			} else {
				data = full
			}
		}
	}

	return
}

/*
isPrimitive returns a Boolean value indicative of one (1) of the
following conditions being satisfied:

  - Instance qualifies the Primitive interface type, or ...
  - Instance bears an "IsPrimitive() bool" method AND returns true
*/
func isPrimitive(target any) (primitive bool) {
	if target != nil {
		// First, try the direct type assertion.
		if _, primitive = target.(Primitive); !primitive {
			// Fallback to reflection.
			t := refTypeOf(target)

			// deref if it's a pointer
			if t.Kind() == reflect.Ptr {
				t = t.Elem()
			}

			// Check both the value and pointer type.
			primitiveInterface := refTypeOf((*Primitive)(nil)).Elem()
			primitive = t.Implements(primitiveInterface) || reflect.PtrTo(t).Implements(primitiveInterface)
		}
	}

	return
}

func createCodecForPrimitive(val any) (c box, ok bool) {
	if c, ok = val.(box); !ok {
		rt := refTypeOf(val)
		if rt.Kind() == reflect.Ptr {
			rt = rt.Elem()
		}

		// Does the generic factory know this primitive?
		var f factories
		if f, ok = master[rt]; ok {
			c = f.newEmpty().(box)
			c.setVal(val)
		}
	}

	return
}
