package asn1plus

import "testing"

func TestNull_encodingRules(t *testing.T) {
	for _, rule := range encodingRules {
		var null Null
		pkt, err := Marshal(null, With(rule))
		if err != nil {
			t.Errorf("%s failed [%s encoding]: %v", t.Name(), rule, err)
			return
		}

		var null2 Null
		if err = Unmarshal(pkt, &null2); err != nil {
			t.Errorf("%s failed [%s decoding]: %v", t.Name(), rule, err)
			return
		}

		want := "05 00"
		if got := pkt.Hex(); got != want {
			t.Errorf("%s failed [%s hex cmp.]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), rule, want, got)
		}
	}
}

func TestNull_codecov(t *testing.T) {
	var null Null
	null.Tag()
	null.Len()
	null.IsPrimitive()
	_ = null.String()
}
