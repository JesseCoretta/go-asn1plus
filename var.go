package asn1plus

/*
var.go contains global variables and constants used throughout this package.
*/

/*
ASN.1 tag constants. These are defined largely for convenience so that
[encoding/asn1] need not be imported by the caller.
*/
const (
	invalidTag          = 0
	TagBoolean          = 1
	TagInteger          = 2
	TagBitString        = 3
	TagOctetString      = 4
	TagNull             = 5
	TagOID              = 6
	TagObjectDescriptor = 7
	TagExternal         = 8
	TagReal             = 9
	TagEnum             = 10
	TagEmbeddedPDV      = 11
	TagUTF8String       = 12
	TagRelativeOID      = 13
	TagTime             = 14
	TagSequence         = 16
	TagSet              = 17
	TagNumericString    = 18
	TagPrintableString  = 19
	TagT61String        = 20
	TagVideotexString   = 21
	TagIA5String        = 22
	TagUTCTime          = 23
	TagGeneralizedTime  = 24
	TagGraphicString    = 25
	TagVisibleString    = 26
	TagGeneralString    = 27
	TagUniversalString  = 28
	TagCharacterString  = 29 // Not yet implemented.
	TagBMPString        = 30
	TagDate             = 31
	TagTimeOfDay        = 32
	TagDateTime         = 33
	TagDuration         = 34
)

/*
ASN.1 class constants. These are defined largely for convenience so that
[encoding/asn1] need not be imported by the caller.
*/
const (
	invalidClass int = iota - 1
	ClassUniversal
	ClassApplication
	ClassContextSpecific
	ClassPrivate
)

/*
ClassNames facilitates access to string ASN.1 class names.
*/
var ClassNames = map[int]string{
	invalidClass:         "INVALID CLASS",
	ClassUniversal:       "UNIVERSAL",
	ClassApplication:     "APPLICATION",
	ClassContextSpecific: "CONTEXT SPECIFIC",
	ClassPrivate:         "PRIVATE",
}

/*
TagNames facilitates access to string ASN.1 tag names.
*/
var TagNames = map[int]string{
	invalidTag:          "INVALID TAG",       //  0
	TagBoolean:          "BOOLEAN",           //  1
	TagInteger:          "INTEGER",           //  2
	TagBitString:        "BIT STRING",        //  3
	TagOctetString:      "OCTET STRING",      //  4
	TagNull:             "NULL",              //  5
	TagOID:              "OBJECT IDENTIFIER", //  6
	TagObjectDescriptor: "OBJECT DESCRIPTOR", //  7
	TagExternal:         "EXTERNAL",          //  8 -- replaced by EmbeddedPDV
	TagReal:             "REAL",              //  9
	TagEnum:             "ENUM",              // 10
	TagEmbeddedPDV:      "EMBEDDED PDV",      // 11
	TagUTF8String:       "UTF8String",        // 12
	TagRelativeOID:      "RelativeOID",       // 13
	TagTime:             "TIME",              // 14
	TagSequence:         "SEQUENCE",          // 16
	TagSet:              "SET",               // 17
	TagNumericString:    "NumericString",     // 18
	TagPrintableString:  "PrintableString",   // 19
	TagT61String:        "T61String",         // 20
	TagVideotexString:   "VideotexString",    // 21 -- obsolete
	TagIA5String:        "IA5String",         // 22
	TagUTCTime:          "UTCTime",           // 23
	TagGeneralizedTime:  "GeneralizedTime",   // 24
	TagGraphicString:    "GraphicString",     // 25 -- deprecated in favor of BMPString, UniversalStirng, UTF8String
	TagVisibleString:    "VisibleString",     // 26
	TagGeneralString:    "GeneralString",     // 27 -- deprecated in favor of BMPString, UniversalString, UTF8String
	TagUniversalString:  "UniversalString",   // 28
	TagCharacterString:  "CharacterString",   // 29
	TagBMPString:        "BMPString",         // 30
	TagDate:             "Date",              // 31
	TagTimeOfDay:        "TimeOfDay",         // 32
	TagDateTime:         "DateTime",          // 33
	TagDuration:         "Duration",          // 34
}

/*
CompoundNames facilitates access to string ASN.1 compound state names.
*/
var CompoundNames = map[bool]string{
	true:  "COMPOUND",
	false: "NOT COMPOUND",
}

// private encoding rule OID global vars
var (
	berOID,
	derOID,
	cerOID ObjectIdentifier
)

var (
	ptrClassUniversal       = new(int)
	ptrClassContextSpecific = new(int)
)

var boolKeywords = map[string]struct{}{
	"explicit":   {},
	"optional":   {},
	"automatic":  {},
	"set":        {},
	"sequence":   {},
	"omitempty":  {},
	"indefinite": {},
}

var classKeywords = map[string]struct{}{
	"application":      {},
	"context-specific": {},
	"context specific": {},
	"private":          {},
}

const hexDigits = "0123456789ABCDEF"

func init() {
	*ptrClassUniversal = ClassUniversal
	*ptrClassContextSpecific = ClassContextSpecific

	berOID, _ = NewObjectIdentifier(2, 1, 1)
	cerOID, _ = NewObjectIdentifier(2, 1, 2, 0)
	derOID, _ = NewObjectIdentifier(2, 1, 2, 1)

	//perOID, _ = NewObjectIdentifier(2, 1, 3, 0, 0)
	//cperOID, _ = NewObjectIdentifier(2.1.3.1.0)
	//ucperOID, _ = NewObjectIdentifier(2.1.3.1.1)
	//uperOID, _ = NewObjectIdentifier(2.1.3.0.1)
}
