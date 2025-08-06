package asn1plus

import (
	"fmt"
	"testing"
)

func TestClassInstance_Unique(t *testing.T) {
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	// Based on 13.12 of ITU-T rec. X.501 (10/2019).
	/*
	   SYNTAX-NAME ::= CLASS {
	    &desc UTF8String,
	    &Type,
	    &id OBJECT IDENTIFIER UNIQUE }
	   WITH SYNTAX {
	    DESC &desc
	    DIRECTORY SYNTAX &Type
	    ID &id }
	*/

	optional := &Options{Optional: true}
	unique := &Options{Unique: true}

	syntax, _ := NewClass("SYNTAX-NAME",
		must(ClassValueField.NewField("&desc", UTF8String(``), optional)),
		must(ClassTypeField.NewField("&Type", nil)), // dynamically typed
		must(ClassValueField.NewField("&id", ObjectIdentifier{}, unique)))

	oidParser := func(x any) (any, error) {
		return NewObjectIdentifier(x)
	}

	descParser := func(x any) (any, error) {
		return NewUTF8String(x)
	}

	// Make two ClassInstance instances, each bearing the same OID
	// in violation of the above mandate regarding OID uniqueness.

	// We can shadow both returns of the first instance since we
	// don't need them.
	_, _ = syntax.New(
		map[string]any{
			"DESC":  "Enhanced Guide",
			"&Type": struct{}{},
			"&id":   "1.3.6.1.4.1.1466.115.121.1.21",
		},
		syntax.FieldHandler("&desc", descParser), // "DESC"
		syntax.FieldHandler("ID", oidParser),     // "&id"
	)

	// Shadow the ClassInstance return, but keep the error just for
	// confirmation.
	_, err := syntax.New(
		map[string]any{
			"DESC":  "Duplicate Enhanced Guide",
			"&Type": struct{}{},
			"&id":   "1.3.6.1.4.1.1466.115.121.1.21", // should VIOLATE uniqueness
		},
		syntax.FieldHandler("&desc", descParser), // "DESC"
		syntax.FieldHandler("ID", oidParser),     // "&id"
	)

	if err == nil {
		t.Fatalf("%s failed: expected ClassInstance duplication error, got nil", t.Name())
	}
}

/*
This example demonstrates a basic X.501 SYNTAX-NAME implementation
using the EnhancedGuide syntax. In particular, the creation of the
"SYNTAX-NAME" [Class] demonstrates the use of <nil> as a prototype,
which the package interprets as an intent to use any type in the
subsequent creation of [ClassInstance] instances.

Note that errors are shadowed in this example for brevity.
*/
func ExampleClassInstance_syntaxFromTemplate() {
	// panicky field constructor for convenience.
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	// Based on 13.12 of ITU-T rec. X.501 (10/2019).
	/*
		SYNTAX-NAME ::= CLASS {
		 &desc UTF8String,
		 &Type,
		 &id OBJECT IDENTIFIER UNIQUE }
		WITH SYNTAX {
		 DESC &desc
		 DIRECTORY SYNTAX &Type
		 ID &id }
	*/

	optional := &Options{Optional: true}

	syntax, _ := NewClass("SYNTAX-NAME",
		must(ClassValueField.NewField("&desc", UTF8String(``), optional)),
		// nil == allow any type in a derived ClassInstance
		must(ClassTypeField.NewField("&Type", nil)),
		must(ClassValueField.NewField("&id", ObjectIdentifier{})))

	// Engage 'WITH SYNTAX' support
	_ = syntax.WithSyntax(map[string]string{
		"DESC":             "&desc",
		"DIRECTORY SYNTAX": "&Type",
		"ID":               "&id",
	})

	// Wrap the standard OID constructor
	// for the "&id" field.
	oidParser := func(x any) (any, error) {
		return NewObjectIdentifier(x)
	}

	// Wrap the standard UTF-8 string constructor
	// for the "&desc" field.
	descParser := func(x any) (any, error) {
		return NewUTF8String(x)
	}

	// this is just a dummy type per 9.2.11 of ITU-T
	// rec X.520 (Enhanced Guide syntax), and is used
	// solely for demonstration purposes here.
	type EnhancedGuide struct {
		ObjectClass string
		Criteria    any
		Subset      int
	}

	eGuide, _ := syntax.New(
		// Set some values of interest. Here, we use
		// alternative names declared via WithSyntax
		// above, mixed with some base names.
		/*
			enhancedGuide SYNTAX-NAME ::= {
			 DESC "Enhanced Guide"
			 DIRECTORY SYNTAX EnhancedGuide
			 ID id-lsx-enhancedGuide }
		*/
		map[string]any{
			"DESC":  "Enhanced Guide",                // "DESC" ("&desc")
			"&Type": (*EnhancedGuide)(nil),           // "DIRECTORY SYNTAX"
			"&id":   "1.3.6.1.4.1.1466.115.121.1.21", // "ID"
		},
		syntax.FieldHandler("&desc", descParser), // "DESC"
		syntax.FieldHandler("ID", oidParser),     // "&id"
	)

	// Grab the values of interest. Here, we use the
	// alternative names declared via WithSyntax
	// above, mixed with some base names.
	desc, _ := eGuide.Field(`&desc`)           // (or "DESC")
	oid, _ := eGuide.Field(`ID`)               // (or "&id")
	typ, _ := eGuide.Field(`DIRECTORY SYNTAX`) // (or "&Type")

	fmt.Printf("%s syntax (%s) expects type %T", desc.(UTF8String), oid.(ObjectIdentifier), typ)
	// Output: Enhanced Guide syntax (1.3.6.1.4.1.1466.115.121.1.21) expects type *asn1plus.EnhancedGuide
}

/*
This example demonstrates the instantiation of an instance of the X.501
ATTRIBUTE class. The resultant instance represents the official 'name'
attribute type (name, 2.5.4.41) as defined in section 2.18 of RFC 4519.
*/
func ExampleClassInstance_attributeFromTemplate() {
	// panicky field constructor for convenience.
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	// For brevity, these are just oversimplified types.
	type (
		AttributeType any
		MatchingRule  struct {
			OID    string
			Name   []string
			Syntax string
		}
		LDAPSyntax struct {
			OID string
		}
		AttributeUsage int
	)

	// First, we create the X.501 ATTRIBUTE class template
	// Note that this need only be done once. We shadow the
	// error here simply for brevity.

	optional := &Options{Optional: true}

	tmpl, _ := NewClass("ATTRIBUTE",
		must(ClassObjectField.NewField("&derivation", (*AttributeType)(nil), optional)),
		must(ClassTypeField.NewField("&Type", (*AttributeType)(nil), optional)),
		must(ClassObjectField.NewField("&equality-match", (*MatchingRule)(nil), optional)),
		must(ClassObjectField.NewField("&ordering-match", (*MatchingRule)(nil), optional)),
		must(ClassObjectField.NewField("&substrings-match", (*MatchingRule)(nil), optional)),
		must(ClassValueField.NewField("&single-valued", false, optional)),
		must(ClassValueField.NewField("&collective", false, optional)),
		must(ClassValueField.NewField("&dummy", false, optional)),
		must(ClassValueField.NewField("&no-user-modification", false, optional)),
		must(ClassValueField.NewField("&usage", AttributeUsage(0), optional)),
		must(ClassValueField.NewField("&ldapSyntax", (*LDAPSyntax)(nil), optional)),
		must(ClassValueField.NewField("&ldapName", []string{}, optional)),
		must(ClassValueField.NewField("&ldapDesc", "", optional)),
		must(ClassValueField.NewField("&obsolete", false, optional)),
		must(ClassValueField.NewField("&id", ObjectIdentifier{})),
	)

	// OPTIONAL: we can define parsers for individual
	// fields of ClassInstance when we initialize cn
	// later on. This is a very watered-down example,
	// and a real-life implementation would probably
	// involve lookups which return proper instances
	// of *MatchingRule, et al, based on input as
	// opposed to "manual crafting" as we do below.

	// Wrap the standard OID constructor for the "&id"
	// and "&ldapSyntax" fields checker
	oidParser := func(x any) (any, error) {
		return NewObjectIdentifier(x)
	}

	// syntax handler for "&ldapSyntax"
	ldapSyntax := func(x any) (any, error) {
		ls := &LDAPSyntax{}
		oid, err := NewObjectIdentifier(x)
		if err == nil {
			ls.OID = oid.String()
			// other fields omitted for brevity,
			// as in real-life they would be
			// populated by a schema lookup
			// of the indicated oid.
		}
		return ls, err
	}

	// matchingRule handler for &equality-match,
	// &ordering-match and &substrings-match.
	matchingRule := func(x any) (any, error) {
		mr := &MatchingRule{}
		oid, err := NewObjectIdentifier(x)
		if err != nil {
			// user may have entered a NAME. In
			// real-life, we'd likely want to
			// resolve it to a numeric OID, so
			// let's pretend thats what we do
			// here :)
		}
		mr.OID = oid.String()
		// omitted other fields, just for brevity.
		return mr, err
	}

	// name(s) handler for "&ldapName"
	nameParser := func(x any) (any, error) {
		var out []string
		if _, ok := x.([]string); ok {
			out = x.([]string)
		} else if _, ok = x.(string); ok {
			out = []string{x.(string)}
		}
		// Optional: user may add a "descr"
		// parser routine here to ensure
		// RFC4512 compliance, non-zero
		// length, et al.
		return out, nil
	}

	// Now we can register as many individual attributes
	// as we wish. Here, we simply register the "name"
	// attribute type (2.5.4.41). Again, the error is
	// shadowed here for brevity.

	Name, _ := tmpl.New(
		map[string]any{
			"&id":               "2.5.4.41",
			"&ldapName":         "name",
			"&equality-match":   "2.5.13.2",                      // caseIgnoreMatch
			"&substrings-match": "2.5.13.4",                      // caseIgnoreSubstringsMatch
			"&ldapSyntax":       "1.3.6.1.4.1.1466.115.121.1.15", // directoryString
		},
		tmpl.FieldHandler("&id", oidParser),
		tmpl.FieldHandler("&ldapName", nameParser),
		tmpl.FieldHandler("&equality-match", matchingRule),
		tmpl.FieldHandler("&substrings-match", matchingRule),
		tmpl.FieldHandler("&ldapSyntax", ldapSyntax),
	)

	// Grab the values of interest. Once again, we shadow
	// error for brevity.
	name, _ := Name.Field(`&ldapName`)
	oid, _ := Name.Field(`&id`)

	fmt.Printf("%s (%s)", name.([]string)[0], oid.(ObjectIdentifier))
	// Output: name (2.5.4.41)
}

func ExampleClass_objectClass() {
	// panicky field constructor for convenience.
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			panic(err)
		}
		return cf
	}

	// For the sake of simplicity, these are
	// just dummy types.
	type (
		AttributeType   any
		ObjectClass     any
		Mandatory       = map[int]*AttributeType
		Optional        = map[int]*AttributeType
		SuperClasses    = map[int]*ObjectClass
		ObjectClassKind int // 0 = structural, 1 = auxiliary, 2 = abstract
	)

	optional := &Options{Optional: true}

	obj, err := NewClass("OBJECT-CLASS",
		must(ClassObjectField.NewField("&SuperClasses", SuperClasses{}, optional)),
		must(ClassValueField.NewField("&kind", ObjectClassKind(0), optional)),
		must(ClassTypeField.NewField("&MandatoryAttributes", Mandatory{}, optional)),
		must(ClassTypeField.NewField("&OptionalAttributes", Optional{}, optional)),
		must(ClassValueField.NewField("&ldapName", []string{}, optional)),
		must(ClassValueField.NewField("&ldapDesc", "", optional)),
		must(ClassValueField.NewField("&id", ObjectIdentifier{})),
	)

	if err != nil {
		panic(err)
	}

	fmt.Println(obj.Name, len(obj.Fields))
	// Output:
	// OBJECT-CLASS 7
}

func TestClass(t *testing.T) {
	tname := t.Name()
	must := func(cf ClassField, err error) ClassField {
		if err != nil {
			t.Fatalf("%s failed: unexpected error: %v", tname, err)
		}
		return cf
	}

	valCF := must(ClassValueField.NewField("&answer", 42))
	dupeCF := must(ClassValueField.NewField("&answer", 42))
	objCF := must(ClassObjectField.NewField("&ptr", (*struct{})(nil), &Options{Optional: true}))

	cl, err := NewClass("TEST-CLASS", valCF, objCF)
	if err != nil {
		t.Fatalf("%s failed: NewClass failed: %v", tname, err)
	}

	if _, err = NewClass(""); err == nil {
		t.Fatalf("%s failed: Unnamed CLASS generated no error", tname)
	}

	_, err = NewClass("DUPLICATE-FIELD-CLASS", valCF, dupeCF, objCF)
	if err == nil {
		t.Fatalf("%s failed: Duplicate CLASS field generated no error", tname)
	}

	got, ok := cl.Field("&answer")
	if !ok || !deepEq(*got, valCF) {
		t.Fatalf("%s Field lookup mismatch: ok=%v got=%+v want=%+v",
			tname, ok, got, valCF)
	}

	if err = cl.WithSyntax(map[string]string{
		"ANSWER":  "&answer",
		"POINTER": "&ptr",
	}); err != nil {
		t.Fatalf("%s failed [WithSyntax]: %v", tname, err)
	}

	altLabel := "ANSWER"
	field, _ := cl.Field(altLabel)
	if field == nil {
		t.Fatalf("%s failed [WithSyntax]: failed to find field %s", tname, altLabel)
	}

	// coverage
	for idx, bogus := range []map[string]string{
		{"BOGUS": "&bogus"},
		{"BOGUS": "bogus"},
		{"ANSWER": "bogus"},
		{"BOGUS": "ANSWER"},
	} {
		if err = cl.WithSyntax(bogus); err == nil {
			t.Fatalf("%s[%d] failed [WithSyntax]: expected error for bogus map, got nil", tname, idx)
		}
	}

	if _, err := ClassValueField.NewField("bad", 1); err == nil {
		t.Fatalf("%s failed: expected error for label without leading '&'", tname)
	}

	badLabelField := ClassField{
		Label: "noAmpersand",
		Kind:  ClassValueField,
		Type:  refTypeOf(0), // any non-nil type
	}
	if _, err := NewClass("BAD1", badLabelField); err == nil {
		t.Fatalf("%s failed: expected error for field label without '&'", tname)
	}

	_, _ = ClassObjectField.NewField("", nil)
	_, _ = ClassObjectField.NewField("", nil)

	nilTypeField := ClassField{
		Label: "&noType",
		Kind:  ClassValueField,
		Type:  nil,
	}
	if _, err := NewClass("BAD2", nilTypeField); err == nil {
		t.Fatalf("%s failed: expected error for field with nil Typ", tname)
	}
}
