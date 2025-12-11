package asn1plus

/*
CharacterString implements [clause 44.5 of ITU-T rec. X.680 (10/2021)].
See below for the formal ASN.1 definition.

Instances of this type are automatically wrapped or unwrapped as
[UNIVERSAL 29] during codec operations. CharacterString is NOT
considered an ASN.1 primitive.

The [Choice] field is pre-registered using the [EmbeddedPDV] "Identification"
semantics.

	[UNIVERSAL 29] SEQUENCE {
	  identification CHOICE {
	    syntaxes SEQUENCE {
	      abstract OBJECT IDENTIFIER,
	      transfer OBJECT IDENTIFIER }
	      -- Abstract and transfer syntax object identifiers --,
	    syntax OBJECT IDENTIFIER
	    -- A single object identifier for identification of the
	    -- abstract and transfer syntaxes --,
	    presentation-context-id INTEGER
	    -- (Applicable only to OSI environments)
	    -- The negotiated OSI presentation context identifies the
	    -- abstract and transfer syntaxes --,
	    context-negotiation SEQUENCE {
	      presentation-context-id INTEGER,
	      transfer-syntax OBJECT IDENTIFIER }
	      -- (Applicable only to OSI environments)
	      -- Context-negotiation in progress, presentation-context-id
	      -- identifies only the
	      -- abstract-syntax, so the transfer syntax shall be specified --,
	    transfer-syntax OBJECT IDENTIFIER
	    -- The type of the value (for example, specification that it is
	    -- the value of an ASN.1 type) is fixed by the application
	    -- designer (and hence known to both sender and receiver). This
	    -- case is provided primarily to support
	    -- selective-field-encryption (or other encoding
	    -- transformations) of an ASN.1 type --,
	    fixed NULL
	    -- The data value is the value of a fixed ASN.1 type (and hence
	    -- known to both sender and receiver) -- },
	  data-value-descriptor ObjectDescriptor OPTIONAL
	  -- This provides human-readable identification of the class of
	  -- the value --,
	  string-value OCTET STRING }
	  ( WITH COMPONENTS {
	  ... ,
	  data-value-descriptor ABSENT } )

[clause 44.5 of ITU-T rec. X.680 (10/2021)]: https://www.itu.int/rec/T-REC-X.680
*/
type CharacterString struct {
	Identification Choice `asn1:"choices:identification"`
	StringValue    OctetString
}

/*
Tag returns the integer constant [TagCharacterString].
*/
func (r CharacterString) Tag() int { return TagCharacterString }

func init() {
	csOpts := &Options{}
	csOpts.SetTag(TagCharacterString).SetClass(0)
	RegisterOverrideOptions(CharacterString{}, csOpts)
}
