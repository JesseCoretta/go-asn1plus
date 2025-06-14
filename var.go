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
	TagCharacterString  = 29
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
	TagUTF8String:       "UTF8 STRING",       // 12
	TagRelativeOID:      "RELATIVE OID",      // 13
	TagTime:             "TIME",              // 14
	TagSequence:         "SEQUENCE",          // 16
	TagSet:              "SET",               // 17
	TagNumericString:    "NUMERIC STRING",    // 18
	TagPrintableString:  "PRINTABLE STRING",  // 19
	TagT61String:        "T61 STRING",        // 20
	TagVideotexString:   "VIDEOTEX STRING",   // 21 -- obsolete
	TagIA5String:        "IA5 STRING",        // 22
	TagUTCTime:          "UTC TIME",          // 23
	TagGeneralizedTime:  "GENERALIZED TIME",  // 24
	TagGraphicString:    "GRAPHIC STRING",    // 25 -- deprecated in favor of BMPString, UniversalStirng, UTF8String
	TagVisibleString:    "VISIBLE STRING",    // 26
	TagGeneralString:    "GENERAL STRING",    // 27 -- deprecated in favor of BMPString, UniversalString, UTF8String
	TagUniversalString:  "UNIVERSAL STRING",  // 28
	TagCharacterString:  "CHARACTER STRING",  // 29
	TagBMPString:        "BMP STRING",        // 30
	TagDate:             "DATE",              // 31
	TagTimeOfDay:        "TIME-OF-DAY",       // 32
	TagDateTime:         "DATE-TIME",         // 33
	TagDuration:         "DURATION",          // 34
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
	perOID ObjectIdentifier
)

func init() {
	derOID, _ = NewObjectIdentifier(2, 1, 2, 1)
	berOID, _ = NewObjectIdentifier(2, 1, 1)
	//perOID, _ = NewObjectIdentifier(2, 1, 3, 0, 0)
	//cerOID, _ = NewObjectIdentifier(2,1,2,0)
	//cperOID, _ = NewObjectIdentifier(2.1.3.1.0)
	//ucperOID, _ = NewObjectIdentifier(2.1.3.1.1)
	//uperOID, _ = NewObjectIdentifier(2.1.3.0.1)
}
