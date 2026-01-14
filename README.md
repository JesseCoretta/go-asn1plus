![asn1plus_600x240](https://github.com/user-attachments/assets/032a0afc-3bcc-4a1e-bd43-16dc3591fa30)

[![Go Report Card](https://goreportcard.com/badge/github.com/JesseCoretta/go-asn1plus)](https://goreportcard.com/report/github.com/JesseCoretta/go-asn1plus) [![wiki](https://img.shields.io/badge/wiki-purple?label=%F0%9F%93%96&cacheSeconds=86400)](https://github.com/JesseCoretta/go-asn1plus/wiki) [![codecov](https://codecov.io/gh/JesseCoretta/go-asn1plus/graph/badge.svg?token=5N6NGLUVJU)](https://codecov.io/gh/JesseCoretta/go-asn1plus) [![CodeQL](https://github.com/JesseCoretta/go-asn1plus/workflows/CodeQL/badge.svg)](https://github.com/JesseCoretta/go-asn1plus/actions/workflows/codeql.yml) [![Clones](https://img.shields.io/badge/dynamic/json?url=https://gist.githubusercontent.com/JesseCoretta/fc9283f4379c4b0b6211de82d01e2cec/raw/asn1plus_clones.json&query=%24.message&label=clones&color=blue)](#) [![Reference](https://pkg.go.dev/badge/github.com/JesseCoretta/go-asn1plus.svg)](https://pkg.go.dev/github.com/JesseCoretta/go-asn1plus) [![X.680](https://img.shields.io/badge/X.680-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.680) [![X.690](https://img.shields.io/badge/X.690-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.690) [![Issues](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-asn1plus/issues) [![Experimental](https://img.shields.io/badge/experimental-blue?logoColor=blue&label=%F0%9F%A7%AA%20%F0%9F%94%AC&labelColor=blue&color=gray)](https://github.com/JesseCoretta/JesseCoretta/blob/main/EXPERIMENTAL.md) [![Volatility Warning](https://img.shields.io/badge/volatile-darkred?label=%F0%9F%92%A5&labelColor=white&color=orange&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/VOLATILE.md) [![Help Animals](https://img.shields.io/badge/help_animals-gray?label=%F0%9F%90%BE%20%F0%9F%98%BC%20%F0%9F%90%B6&labelColor=yellow)](https://github.com/JesseCoretta/JesseCoretta/blob/main/DONATIONS.md) [![Help Wanted](https://img.shields.io/badge/Help_Wanted-red?label=%F0%9F%9A%A8&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/HELPWANTED.md)

Package `asn1plus` ("ASN.1+") implements an extensible Go-based ASN.1 API supporting subsets of ITU-T X-Series Recommendations [680](https://www.itu.int/rec/T-REC-X.680) and [690](https://www.itu.int/rec/T-REC-X.690).

## License

The `asn1plus` package is released under the terms of the MIT license. See the LICENSE file in the repository root for details.

## Status

This package is under heavy development and is **HIGHLY EXPERIMENTAL**. As such, it should NOT be used in a mission-critical capacity at this time.

Go version 1.21 or later is required

## Donations for animal/environmental causes

If you or your organization use my software regularly and find it useful, I only ask that you donate to animal shelters, non-profit environmental entities or similar. If you cannot afford a monetary contribution to these causes, please volunteer at animal shelters and/or visit kill shelters for the purpose of liberating animals unfairly awaiting execution.

## Help Wanted!

As indicated by the above badge, I am actively looking for experienced open source volunteers who have a keen grasp of ASN.1, encoding rules and other relevant components.

Interested? [Email me](mailto:jesse.coretta@icloud.com).

## Relation to encoding/asn1

This package has no dependence upon the `encoding/asn1` package, as this package is meant to serve as an alternative.

## Features

 - Fast ASN.1 [BER](## "Basic Encoding Rules"), [CER](## "Canonical Encoding Rules") and [DER](## "Distinguished Encoding Rules") encoding/decoding
 - Flexible build system
 - Full ASN.1 primitive type support -- twenty six (26) types are implemented, such as `OctetString`, `Time`, `Real` and many others (including legacy/deprecated types)
 - `SET` and `SEQUENCE` support
 - Constraints -- Flexible ASN.1 constraint logic has been implemented for maximum control
 - Choice support, with custom interface registration bindings to concrete types
 - Intuitive, easy to use
 - Well documented, containing many useful examples

## Build Tags

This package supports flexible build instructions. By default, this package enables all features _except_ debugging.

But in certain cases it may be advantageous to disable certain elements, such as [CER](## "Canonical Encoding Rules") or [DER](## "Distinguished Encoding Rules") encoding, or even to disable deprecated ASN.1 types.

Regardless of the permutation, this package offers build tags to make the task easy. Whether you're building an executable -- even a simple `main.go` -- or, if you're running the included test suite directly, it is painless to enable/disable select features.

| Build Tag       | Description |
| :-------------  | :---------- |
| `asn1_no_adapter_pf` | Do not implement prefabricated type bindings  |
| `asn1_no_cer`      | Do not implement [CER](## "Canonical Encoding Rules") encoding |
| `asn1_no_constr_pf` | Do not implement prefabricated constraint functions |
| `asn1_debug`    | Enable debug tracer; use with extreme caution |
| `asn1_no_der`      | Do not implement [DER](## "Distinguished Encoding Rules") encoding |
| `asn1_no_dprc`     | Do not implement deprecated/obsolete ASN.1 types |

To utilize these tags, simply invoke the `-tags` command-line option when executing the `go` binary, e.g.:

```
## Test without type adapters prefabs and without deprecated types
$ go test -tags asn1_no_adapter_pf,asn1_no_dprc ./...

## Build main.go without CER support
$ go build -tags asn1_no_cer main.go

## Run main.go without constraint prefabs
$ go run -tags asn1_no_constr_pf main.go
```

Depending on the tags invoked, the elapsed time of subsequent runs of the test suite will vary.

Note that certain features -- namely [BER](## "Basic Encoding Rules") encoding -- cannot be disabled.

## Dependencies

This package relies upon the following packages from the standard library:

  - `bytes`
  - `encoding/binary`
  - `encoding/hex`
  - `errors`
  - `fmt`<sup><sup>†</sup></sup>
  - `io`
  - `math`
  - `math/big`
  - `math/bits`
  - `math/rand` <sup><sup>‡</sup></sup>
  - `os` <sup><sup>‡</sup></sup>
  - `reflect`
  - `runtime` <sup><sup>‡</sup></sup>
  - `slices`
  - `strconv`
  - `strings`
  - `sync`
  - `sync/atomic`
  - `testing`
  - `time`
  - `unicode`
  - `unicode/utf8`
  - `unicode/utf16`
  - `unsafe`

This package relies upon the following packages from the `golang/x/exp` library:

  - `constraints`<sup><sup>⹋</sup></sup>

<sup>
  <sup><b>†</b> - used ONLY for testing/examples</sup><br>
  <sup><b>‡</b> - used ONLY when debugging is enabled</sup><br>
  <sup><b>⹋</b> - used ONLY when prefabricated constraints are loaded</sup><br>
</sup>

## Constraints

The ASN.1 specification allows constraints to be applied to values. This might include restricting the allowed character set of a string beyond its base definition (for instance, forbid lower-case letters).

This package honors this capability, and allows `Constraint`s to be custom-written and applied in two different ways:

 - Manually via a type constructor (e.g.: `NewOctetString(myValue, constraintFunc1, constraintFunc2)`), or ...
 - Automatically via an `Options` instance -- whether hand-crafted or specified via struct tag (e.g.: `asn1:"constraint:constraintFunc1,..."`)

A `Constraint` may be used ad hoc, or as part of a `ConstraintGroup`, which iterates any number of `Constraint` functions in the order in which they are specified.

When using any number of `Constraint`s via `Options`, the `Constraint` function MUST be pre-registered using the package-level `RegisterTaggedConstraint` or `RegisterTaggedConstraintGroup` functions.

There are many examples compiled into the package on this topic.

Prefabricated `Constraint` instances can be excluded from builds using the `asn1_no_constr_pf` build tag.

## Native Go Type Support

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

Prefabricated adapter bindings can be excluded from builds using the `asn1_no_adapter_pf` build tag.

