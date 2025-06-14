![image](https://github.com/user-attachments/assets/2bd71a3f-bd29-4c33-9c77-673279281db8)

[![X.680](https://img.shields.io/badge/X.680-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.680) [![X.690](https://img.shields.io/badge/X.690-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.690) [![Issues](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-dirsyn/issues) [![Experimental](https://img.shields.io/badge/experimental-blue?logoColor=blue&label=%F0%9F%A7%AA%20%F0%9F%94%AC&labelColor=blue&color=gray)](https://github.com/JesseCoretta/JesseCoretta/blob/main/EXPERIMENTAL.md) [![Volatility Warning](https://img.shields.io/badge/volatile-darkred?label=%F0%9F%92%A5&labelColor=white&color=orange&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/VOLATILE.md) [![Help Animals](https://img.shields.io/badge/help_animals-gray?label=%F0%9F%90%BE%20%F0%9F%98%BC%20%F0%9F%90%B6&labelColor=yellow)](https://github.com/JesseCoretta/JesseCoretta/blob/main/DONATIONS.md) [![Help Wanted](https://img.shields.io/badge/Help_Wanted-red?label=%F0%9F%9A%A8&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/HELPWANTED.md)

Package `asn1plus` ("ASN.1+") implements an extensible Go-based ASN.1 API supporting subsets of ITU-T X-Series Recommendations [680](https://www.itu.int/rec/T-REC-X.680) and [690](https://www.itu.int/rec/T-REC-X.690).

## License

The `asn1plus` package is released under the terms of the MIT license. See the LICENSE file in the repository root for details.

## Status

This package is under heavy development and is **HIGHLY EXPERIMENTAL**. As such, it should NOT be used in a mission-critical capacity at this time.

## Help Wanted!

As indicated by the above badge, I am actively looking for experienced open source volunteers who have a keen grasp of ASN.1, encoding rules and other relevant components.

Interested? [Email me](mailto:jesse.coretta@icloud.com).

## Relation to encoding/asn1

This package has no dependence upon the `encoding/asn1` package, as this package is meant to serve as an alternative.

## Encoding rules

`asn1plus` presently supports [BER](## "Basic Encoding Rules") and [DER](## "Distinguished Encoding Rules").

Other encoding rules, such as [PER/APER](## "[Aligned] Packed Encoding Rules") and [UPER](## "Unaligned Packed Encoding Rules"), may follow.

## Features

 - Fast ASN.1 encoding/decoding
   - With parallel executions disabled and no cache utilization, this package runs well over 300 unit tests in approximately 14-16ms
 - Full ASN.1 primitive type support -- twenty six (26) types are implemented, such as`OctetString`, `Time`, `Real` and many others (including legacy/deprecated types)
 - `SET` and `SEQUENCE` support
 - Constraints -- Flexible ASN.1 constraint logic has been implemented for maximum control
 - Intuitive, easy to use
 - Well documented, containing many useful examples

## Dependencies

This package relies upon the following packages from the standard library:

  - `bytes`
  - `encoding/binary`
  - `encoding/hex`
  - `errors`
  - `fmt`<sup><sup>†</sup></sup>
  - `math`
  - `math/big`
  - `math/bits`
  - `reflect`
  - `sort`
  - `strconv`
  - `strings`
  - `sync`
  - `testing`
  - `time`
  - `unicode`
  - `unicode/utf8`
  - `unicode/utf16`

This package relies upon the following packages from the `golang/x/exp` library:

  - `constraints`<sup><sup>††</sup></sup>

<sup>
  <sup><b>†</b>  - used ONLY for testing/examples</sup><br>
  <sup><b>††</b> - WARNING: Experimental!</sup><br>
</sup>

## Constraints

The ASN.1 specification allows constraints to be applied to values. This might include restricting the allowed character set of a string beyond its base definition (for instance, forbid lower-case letters).

This package honors this capability, and allows `Constraint`s to be custom-written and applied in two different ways:

 - Manually via a type constructor (e.g.: `NewOctetString(myValue, constraintFunc1, constraintFunc2)`), or ...
 - Automatically via an `Options` instance -- whether hand-crafted or specified via struct tag (e.g.: `asn1:"constraint:constraintFunc1,..."`)

A `Constraint` may be used ad hoc, or as part of a `ConstraintGroup`, which iterates any number of `Constraint` functions in the order in which they are specified.

When using any number of `Constraint`s via `Options`, the `Constraint` function MUST be pre-registered using the package-level `RegisterTaggedConstraint` or `RegisterTaggedConstraintGroup` functions.

There are many examples compiled into the package on this topic.

# Native Go Type Support

In addition to the ASN.1 primitive types defined in this package, users may opt for standard Go types such as `[]byte`, `string`, `int` and a few others to be supported via internal "type adapters".

This means that the following two `SEQUENCE` instances are functionally identical:

```
// Use readily identifiable ASN.1 primitive types
type MySequence struct {
	Name  PrintableString
	Email IA5String
}
```

```
// Use Go types with tagged instructions
type MySequence struct {
	Name  string `asn1:"printable"`
	Email string `asn1:"ia5"`
}
```

Subsequent encoded values will be identical.

The caveat to using tagged instructions in this manner -- as opposed to actual ASN.1 types as used in the first `MySequence` example -- is that the `Unmarshal` function will need to receive the same instructions which `Marshal` received. Thus, if we attempt to `Unmarshal` into a `SEQUENCE` with untagged string fields and without instructions, defaults may be erroneously applied (e.g.: a UTF-8 STRING is mistaken for an OCTET STRING, or some other such permutation). This is not an issue when using actual ASN.1 types, as the compiler will recognize them and decode them properly automatically.
