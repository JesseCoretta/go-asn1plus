package asn1plus

/*
pdv.go contains all types and methods pertaining to the ASN.1
EMBEDDED PDV type.
*/

/*
Syntaxes represents the abstract and transfer syntax [ObjectIdentifier] values
within an [EmbeddedPDV] Identification [Choice] instance.
*/
type Syntaxes struct {
	Abstract ObjectIdentifier
	Transfer ObjectIdentifier
}

/*
ContextNegotiation implements the OSI presentation context negotiation for an
[EmbeddedPDV] instance.
*/
type ContextNegotiation struct {
	PresentationContextID Integer
	TransferSyntax        ObjectIdentifier
}

/*
identification implements the ASN.1 CHOICE for the [EmbeddedPDV]
"Identification" field to be used to determine an appropriate
Choice to write.
*/
var identification Choices

/*
EmbeddedPDV implements the [ITU-T Rec. X.680] ASN.1 EMBEDDED PDV type (tag 11).

The EmbeddedPDV (Presentation Data Values) type is used to represent data that
includes both syntax and identification information, making it useful for
transferring structured presentation data.

This type is often employed in scenarios where different encoding rules might
apply to a set of values, helping systems interpret and process data correctly
across different protocols.

	EmbeddedPDV ::= [UNIVERSAL 11] IMPLICIT SEQUENCE {
	identification CHOICE {
	  syntaxes SEQUENCE {
	    abstract OBJECT IDENTIFIER,
		 transfer OBJECT IDENTIFIER }
		 -- Abstract and transfer syntax object identifiers --,
		 syntax OBJECT IDENTIFIER
		 -- A single object identifier for identification of the abstract
		 -- and transfer syntaxes --,
		 presentation-context-id INTEGER
		 -- (Applicable only to OSI environments)
		 -- The negotiated OSI presentation context identifies the
		 -- abstract and transfer syntaxes --,
		 context-negotiation SEQUENCE {
			presentation-context-id INTEGER,
			transfer-syntax OBJECT IDENTIFIER }
		 --(Applicable only to OSI environments)
		 -- Context-negotiation in progress, presentation-context-id
		 -- identifies only the abstract syntax
		 -- so the transfer syntax shall be specified --,
		 transfer-syntax OBJECT IDENTIFIER
		 -- The type of the value (for example, specification that it is
		 -- the value of an ASN.1 type)
		 -- is fixed by the application designer (and hence known to both
		 -- sender and receiver). This
		 -- case is provided primarily to support
		 -- selective-field-encryption (or other encoding
		 -- transformations) of an ASN.1	type --,
		 fixed NULL
		 -- The data value is the value of a fixed ASN.1 type (and hence
		 -- known to both sender
		 -- and receiver) --
	  },
	  data-value-descriptor ObjectDescriptor OPTIONAL
	  -- This provides human-readable identification of the class of the
	  -- value --,
	  data-value OCTET STRING }
	( WITH COMPONENTS {
	       ... , data-value-descriptor ABSENT } )

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type EmbeddedPDV struct {
	Identification      Choice            `asn1:"choices:identification"`
	DataValueDescriptor *ObjectDescriptor `asn1:"optional,absent"`
	DataValue           OctetString
	Extensions          []TLV `asn1:"..."`
}

/*
Tag returns the integer constant [TagEmbeddedPDV].
*/
func (r EmbeddedPDV) Tag() int { return TagEmbeddedPDV }

func init() {
	// Initialize an EmbeddedPDV/External Identification
	// CHOICE registry at start of runtime.
	identification = NewChoices()
	o := &Options{Explicit: true}

	identification.Register(nil, Syntaxes{}, o.SetTag(0))
	identification.Register(nil, ObjectIdentifier{}, o.SetTag(1))
	identification.Register(nil, Integer{}, o.SetTag(2))
	identification.Register(nil, ContextNegotiation{}, o.SetTag(3))
	identification.Register(nil, ObjectIdentifier{}, o.SetTag(4))
	identification.Register(nil, Null{}, o.SetTag(5))
	RegisterChoices("identification", identification)

	pdvOpts := &Options{}
	pdvOpts.SetTag(TagEmbeddedPDV).SetClass(1)
	RegisterOverrideOptions(EmbeddedPDV{}, pdvOpts)
}
