package asn1plus

import "testing"

func TestSequence_WithComponents(t *testing.T) {
	/*
		MySequence ::= SEQUENCE {
			field0 UTF8String OPTIONAL,
			field1 UTF8String OPTIONAL,
			field2 UTF8String OPTIONAL
		} (WITH COMPONENTS {
			field1 ABSENT,
			field2 PRESENT
		})
	*/

	type MySequence struct {
		Field0 UTF8String `asn1:"optional"`
		Field1 UTF8String `asn1:"optional"`
		Field2 UTF8String `asn1:"optional"`
	}

	mine := MySequence{
		Field0: UTF8String("testing0"),
		Field1: UTF8String("testing1"), // This violates the above constraints
		Field2: UTF8String("testing2"),
	}

	RegisterWithComponents("MySequence", map[string]string{
		//Field0 is inconsequential
		"Field1": "ABSENT",
		"Field2": "PRESENT",
	})

	pkt, err := Marshal(mine)
	if err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	var mine2 MySequence
	opts := &Options{WithComponents: []string{"MySequence"}} // case is not significant
	if err = Unmarshal(pkt, &mine2, With(opts)); err == nil {
		t.Fatalf("%s failed: expected 'WITH COMPONENTS' constraint violation, got nil", t.Name())
	}
}
