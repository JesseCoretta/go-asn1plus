package asn1plus

import (
	"fmt"
	"testing"
)

func TestNewBoolean(t *testing.T) {
	var b bool
	for idx, boo := range []any{
		!b,
		&b,
		`true`,
		`TRUE`,
		byte(0xff),
		0,
		1,
	} {
		if B, err := NewBoolean(boo); err != nil {
			t.Errorf("%s[%d] failed [Boolean parse]: %v", t.Name(), idx, err)
		} else {
			B.IsPrimitive()
			B.Tag()
			_ = B.String()

			for _, rule := range encodingRules {
				var pkt Packet
				if pkt, err = Marshal(B, With(rule)); err != nil {
					t.Errorf("%s[%d] failed [%s encoding]: %v", t.Name(), idx, rule, err)
					continue
				}

				if err != nil {
					t.Errorf("%s[%d] failed [%s FullBytes()]: %v", t.Name(), idx, rule, err)
				}

				var B2 Boolean
				if err = Unmarshal(pkt, &B2); err != nil {
					t.Errorf("%s[%d] failed [%s decoding]: %v", t.Name(), idx, rule, err)
					continue
				}

				if B != B2 {
					t.Errorf("%s[%d] failed [%s Boolean string cmp.]:\n\twant: %t\n\tgot:  %t",
						t.Name(), idx, rule, B, B2)
					continue
				}
			}
		}
	}
}

func TestBoolean_codecov(t *testing.T) {
	_, _ = NewBoolean(struct{}{})
}

func ExampleNewBoolean() {
	// accepts bool, *bool, Boolean, byte (0x00 or 0xFF),
	// or any valid strconv.ParseBool string input.
	bewl, err := NewBoolean("false")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%T was %t, ", bewl, bewl)

	bewl = Boolean(true)
	fmt.Printf("but is now %t.\n", bewl)
	// Output: asn1plus.Boolean was false, but is now true.
}

func ExampleBoolean_withConstraint() {
	constraint := LiftConstraint(func(b Boolean) Boolean { return b },
		func(b Boolean) (err error) {
			if !b.Bool() {
				err = fmt.Errorf("Constraint violation: Boolean must be true")
			}
			return
		})

	if _, err := NewBoolean("false", constraint); err != nil {
		fmt.Println(err)
		return
	}
	// Output: Constraint violation: Boolean must be true
}
