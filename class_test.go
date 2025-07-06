package asn1plus

import (
	"fmt"
	"testing"
)

func ExampleClass_objectClass() {
	// panicky field constructor for convenience.
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	type (
		AttributeType   interface{}
		Row             = map[string]any
		RowSet          []*Row
		ObjectClassKind int
	)

	obj, err := NewClass("OBJECT-CLASS",
		must(ClassObjectField.NewField("&Superclasses", RowSet(nil), true)),
		must(ClassValueField.NewField("&kind", ObjectClassKind(0), true)),
		must(ClassTypeField.NewField("&MandatoryAttributes", (*AttributeType)(nil), true)),
		must(ClassTypeField.NewField("&OptionalAttributes", (*AttributeType)(nil), true)),
		must(ClassValueField.NewField("&ldapName", []string{}, true)),
		must(ClassValueField.NewField("&ldapDesc", "", true)),
		must(ClassValueField.NewField("&id", ObjectIdentifier{}, false)),
	)

	if err != nil {
		panic(err)
	}

	fmt.Println(obj.Name, len(obj.Fields))
	// Output:
	// OBJECT-CLASS 7
}

func ExampleClass_attributeType() {
	// panicky field constructor for convenience.
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	type (
		AttributeType  interface{}
		Row            = map[string]any
		MatchingRule   struct{}
		AttributeUsage int
	)

	attr, err := NewClass("ATTRIBUTE",
		must(ClassObjectField.NewField("&derivation", (*Row)(nil), true)),
		must(ClassTypeField.NewField("&Type", (*AttributeType)(nil), true)),
		must(ClassObjectField.NewField("&equality-match", MatchingRule{}, true)),
		must(ClassObjectField.NewField("&ordering-match", MatchingRule{}, true)),
		must(ClassObjectField.NewField("&substrings-match", MatchingRule{}, true)),
		must(ClassValueField.NewField("&single-valued", false, true)),
		must(ClassValueField.NewField("&collective", false, true)),
		must(ClassValueField.NewField("&dummy", false, true)),
		must(ClassValueField.NewField("&no-user-modification", false, true)),
		must(ClassValueField.NewField("&usage", AttributeUsage(0), true)),
		must(ClassValueField.NewField("&ldapSyntax", ObjectIdentifier{}, true)),
		must(ClassValueField.NewField("&ldapName", []string{}, true)),
		must(ClassValueField.NewField("&ldapDesc", "", true)),
		must(ClassValueField.NewField("&obsolete", false, true)),
		must(ClassValueField.NewField("&id", ObjectIdentifier{}, false)),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(attr.Name, len(attr.Fields))
	// Output:
	// ATTRIBUTE 15
}

func TestClass(t *testing.T) {
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return cf
	}

	valCF := must(ClassValueField.NewField("&answer", 42, false))
	dupeCF := must(ClassValueField.NewField("&answer", 42, false))
	objCF := must(ClassObjectField.NewField("&ptr", (*struct{})(nil), true))

	cl, err := NewClass("TEST-CLASS", valCF, objCF)
	if err != nil {
		t.Fatalf("NewClass failed: %v", err)
	}

	if _, err = NewClass(""); err == nil {
		t.Fatalf("Unnamed CLASS generated no error")
	}

	_, err = NewClass("DUPLICATE-FIELD-CLASS", valCF, dupeCF, objCF)
	if err == nil {
		t.Fatalf("Duplicate CLASS field generated no error")
	}

	got, ok := cl.Field("&answer")
	if !ok || !deepEq(*got, valCF) {
		t.Fatalf("Field lookup mismatch: ok=%v got=%+v want=%+v", ok, got, valCF)
	}

	cl = cl.WithSyntax("ID &answer")
	if cl.Syntax != "ID &answer" {
		t.Fatalf("WithSyntax failed: got %q", cl.Syntax)
	}

	if _, err := ClassValueField.NewField("bad", 1, false); err == nil {
		t.Fatalf("expected error for label without leading '&'")
	}

	if _, err := ClassValueField.NewField("&nilProto", nil, false); err == nil {
		t.Fatalf("expected error for nil prototype")
	}

	badLabelField := ClassField{
		Label: "noAmpersand",
		Kind:  ClassValueField,
		Typ:   refTypeOf(0), // any non-nil type
	}
	if _, err := NewClass("BAD1", badLabelField); err == nil {
		t.Fatalf("expected error for field label without '&'")
	}

	_, _ = ClassObjectField.NewField("", nil, false)
	_, _ = ClassObjectField.NewField("", nil, false)

	nilTypeField := ClassField{
		Label: "&noType",
		Kind:  ClassValueField,
		Typ:   nil,
	}
	if _, err := NewClass("BAD2", nilTypeField); err == nil {
		t.Fatalf("expected error for field with nil Typ")
	}
}
