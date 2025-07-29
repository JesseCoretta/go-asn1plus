![asn1plus_600x240](https://github.com/user-attachments/assets/032a0afc-3bcc-4a1e-bd43-16dc3591fa30)


[![Go Report Card](https://goreportcard.com/badge/github.com/JesseCoretta/go-asn1plus)](https://goreportcard.com/report/github.com/JesseCoretta/go-asn1plus) [![codecov](https://codecov.io/gh/JesseCoretta/go-asn1plus/graph/badge.svg?token=5N6NGLUVJU)](https://codecov.io/gh/JesseCoretta/go-asn1plus) [![CodeQL](https://github.com/JesseCoretta/go-asn1plus/workflows/CodeQL/badge.svg)](https://github.com/JesseCoretta/go-asn1plus/actions/workflows/codeql.yml) [![Clones](https://img.shields.io/badge/dynamic/json?url=https://gist.githubusercontent.com/JesseCoretta/fc9283f4379c4b0b6211de82d01e2cec/raw/asn1plus_clones.json&query=%24.message&label=clones&color=blue)](#) [![Reference](https://pkg.go.dev/badge/github.com/JesseCoretta/go-asn1plus.svg)](https://pkg.go.dev/github.com/JesseCoretta/go-asn1plus) [![X.680](https://img.shields.io/badge/X.680-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.680) [![X.690](https://img.shields.io/badge/X.690-red?label=%F0%9F%94%A2&cacheSeconds=86400)](https://www.itu.int/rec/T-REC-X.690) [![Issues](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-asn1plus/issues) [![Experimental](https://img.shields.io/badge/experimental-blue?logoColor=blue&label=%F0%9F%A7%AA%20%F0%9F%94%AC&labelColor=blue&color=gray)](https://github.com/JesseCoretta/JesseCoretta/blob/main/EXPERIMENTAL.md) [![Volatility Warning](https://img.shields.io/badge/volatile-darkred?label=%F0%9F%92%A5&labelColor=white&color=orange&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/VOLATILE.md) [![Help Animals](https://img.shields.io/badge/help_animals-gray?label=%F0%9F%90%BE%20%F0%9F%98%BC%20%F0%9F%90%B6&labelColor=yellow)](https://github.com/JesseCoretta/JesseCoretta/blob/main/DONATIONS.md) [![Help Wanted](https://img.shields.io/badge/Help_Wanted-red?label=%F0%9F%9A%A8&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/HELPWANTED.md)

Package `asn1plus` ("ASN.1+") implements an extensible Go-based ASN.1 API supporting subsets of ITU-T X-Series Recommendations [680](https://www.itu.int/rec/T-REC-X.680) and [690](https://www.itu.int/rec/T-REC-X.690).

## License

The `asn1plus` package is released under the terms of the MIT license. See the LICENSE file in the repository root for details.

## Status

This package is under heavy development and is **HIGHLY EXPERIMENTAL**. As such, it should NOT be used in a mission-critical capacity at this time.

Go version 1.21 or later is required

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

## Performance

This section contains various benchmark and utilization commands.

### Package Benchmarks With Allocation Counts

```
$ go test -run=^$ -bench=. -benchmem ./...

goos: linux
goarch: amd64
pkg: github.com/JesseCoretta/go-asn1plus
cpu: 11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz
BenchmarkEncodeDirectoryString-8   	 1269742	       903.4 ns/op	     248 B/op	      14 allocs/op
BenchmarkDecodeDirectoryString-8   	 1000000	      1093 ns/op	     488 B/op	      23 allocs/op
BenchmarkVideotexConstructor-8     	25877163	        39.20 ns/op	       0 B/op	       0 allocs/op
```

### CPU/Heap Profiles During Benchmarks

```
$ go test -run=^$ -bench=. -cpuprofile=cpu.out -memprofile=mem.out ./...

goos: linux
goarch: amd64
pkg: github.com/JesseCoretta/go-asn1plus
cpu: 11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz
BenchmarkEncodeDirectoryString-8   	 1000000	      1045 ns/op
BenchmarkDecodeDirectoryString-8   	 1000000	      1202 ns/op
BenchmarkVideotexConstructor-8     	27253896	        44.13 ns/op
PASS
ok  	github.com/JesseCoretta/go-asn1plus	3.713s
```

### Top CPU Consumers

```
$ go tool pprof -top cpu.out

File: go-asn1plus.test
Type: cpu
Time: Jun 16, 2025 at 8:35pm (PDT)
Duration: 3.71s, Total samples = 3.58s (96.55%)
Showing nodes accounting for 3.29s, 91.90% of 3.58s total
Dropped 64 nodes (cum <= 0.02s)
      flat  flat%   sum%        cum   cum%
     0.42s 11.73% 11.73%      0.65s 18.16%  runtime.stringtoslicerune
     0.31s  8.66% 20.39%      0.31s  8.66%  github.com/JesseCoretta/go-asn1plus.isVideotex (inline)
     0.29s  8.10% 28.49%      0.59s 16.48%  runtime.mallocgc
     0.22s  6.15% 34.64%      1.18s 32.96%  github.com/JesseCoretta/go-asn1plus.NewVideotexString
     0.20s  5.59% 40.22%      0.20s  5.59%  runtime.decoderune
     0.11s  3.07% 43.30%      0.11s  3.07%  internal/abi.Name.ReadVarint (inline)
     0.11s  3.07% 46.37%      0.42s 11.73%  runtime.growslice
     0.11s  3.07% 49.44%      0.11s  3.07%  runtime.nextFreeFast (inline)
     0.08s  2.23% 51.68%      0.08s  2.23%  runtime.duffcopy
     0.08s  2.23% 53.91%      0.08s  2.23%  runtime.resolveNameOff
     0.08s  2.23% 56.15%      0.08s  2.23%  sync.(*poolChain).popTail
     0.07s  1.96% 58.10%      0.07s  1.96%  runtime.(*mspan).writeHeapBitsSmall
     0.06s  1.68% 59.78%      1.24s 34.64%  github.com/JesseCoretta/go-asn1plus.BenchmarkVideotexConstructor
     0.05s  1.40% 61.17%      0.28s  7.82%  github.com/JesseCoretta/go-asn1plus.EncodingRule.New
     0.05s  1.40% 62.57%      0.53s 14.80%  github.com/JesseCoretta/go-asn1plus.mkerrf
     0.05s  1.40% 63.97%      0.37s 10.34%  reflect.implements
     0.05s  1.40% 65.36%      0.13s  3.63%  reflect.resolveNameOff
     0.05s  1.40% 66.76%      0.05s  1.40%  runtime.memmove
     0.05s  1.40% 68.16%      0.05s  1.40%  runtime.roundupsize (inline)
     0.04s  1.12% 69.27%      0.46s 12.85%  github.com/JesseCoretta/go-asn1plus.isPrimitive
     0.04s  1.12% 70.39%      0.04s  1.12%  runtime.duffzero
     0.04s  1.12% 71.51%      0.04s  1.12%  runtime.mapaccess2_faststr
     0.04s  1.12% 72.63%      0.05s  1.40%  runtime.resolveTypeOff
     0.03s  0.84% 73.46%      0.05s  1.40%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).Append
     0.03s  0.84% 74.30%      0.03s  0.84%  github.com/JesseCoretta/go-asn1plus.setPacketOffset
     0.03s  0.84% 75.14%      0.14s  3.91%  internal/abi.Name.Name
     0.03s  0.84% 75.98%      0.40s 11.17%  reflect.(*rtype).Implements
     0.03s  0.84% 76.82%      0.03s  0.84%  reflect.typedmemmove
     0.03s  0.84% 77.65%      0.03s  0.84%  runtime.deductAssistCredit
     0.03s  0.84% 78.49%      0.03s  0.84%  runtime.memclrNoHeapPointers
     0.03s  0.84% 79.33%      0.12s  3.35%  sync.(*Pool).getSlow
     0.02s  0.56% 79.89%      0.10s  2.79%  github.com/JesseCoretta/go-asn1plus.EncodingRule.newTLV (inline)
     0.02s  0.56% 80.45%      0.79s 22.07%  github.com/JesseCoretta/go-asn1plus.unmarshalSequence
     0.02s  0.56% 81.01%      0.07s  1.96%  reflect.resolveTypeOff
     0.02s  0.56% 81.56%      0.02s  0.56%  runtime.(*mspan).init
     0.02s  0.56% 82.12%      0.02s  0.56%  runtime.futex
     0.02s  0.56% 82.68%      0.09s  2.51%  runtime.mapaccess2
     0.02s  0.56% 83.24%      0.29s  8.10%  runtime.newobject
     0.02s  0.56% 83.80%      0.03s  0.84%  runtime.strequal
     0.02s  0.56% 84.36%      0.04s  1.12%  runtime.typehash
     0.02s  0.56% 84.92%      0.36s 10.06%  strings.(*Builder).WriteString (inline)
     0.02s  0.56% 85.47%      0.12s  3.35%  sync.(*Map).Load
     0.02s  0.56% 86.03%      0.02s  0.56%  sync.(*poolChain).popHead
     0.01s  0.28% 86.31%      0.04s  1.12%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).SetOffset
     0.01s  0.28% 86.59%      0.11s  3.07%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).TLV
     0.01s  0.28% 86.87%      1.22s 34.08%  github.com/JesseCoretta/go-asn1plus.BenchmarkDecodeDirectoryString
     0.01s  0.28% 87.15%      0.02s  0.56%  github.com/JesseCoretta/go-asn1plus.effectiveTag
     0.01s  0.28% 87.43%      0.13s  3.63%  github.com/JesseCoretta/go-asn1plus.encodeTLV
     0.01s  0.28% 87.71%      0.10s  2.79%  github.com/JesseCoretta/go-asn1plus.getTLV
     0.01s  0.28% 87.99%      0.75s 20.95%  github.com/JesseCoretta/go-asn1plus.marshalPrimitive
     0.01s  0.28% 88.27%      1.14s 31.84%  github.com/JesseCoretta/go-asn1plus.unmarshalValue
     0.01s  0.28% 88.55%      0.20s  5.59%  github.com/JesseCoretta/go-asn1plus.writeTLV
     0.01s  0.28% 88.83%      0.04s  1.12%  reflect.(*interfaceType).nameOff (inline)
     0.01s  0.28% 89.11%      0.04s  1.12%  reflect.(*interfaceType).typeOff (inline)
     0.01s  0.28% 89.39%      0.05s  1.40%  reflect.(*rtype).String
     0.01s  0.28% 89.66%      0.07s  1.96%  reflect.Value.Interface (inline)
     0.01s  0.28% 89.94%      0.06s  1.68%  reflect.packEface
     0.01s  0.28% 90.22%      0.07s  1.96%  runtime.(*mcache).nextFree
     0.01s  0.28% 90.50%      0.04s  1.12%  runtime.(*mcentral).cacheSpan
     0.01s  0.28% 90.78%      0.02s  0.56%  runtime.(*spanSet).push
     0.01s  0.28% 91.06%      0.08s  2.23%  runtime.heapSetType
     0.01s  0.28% 91.34%      0.02s  0.56%  runtime.scanobject
     0.01s  0.28% 91.62%      0.27s  7.54%  sync.(*Pool).Get
     0.01s  0.28% 91.90%      0.02s  0.56%  sync.(*Pool).pin
         0     0% 91.90%      1.03s 28.77%  github.com/JesseCoretta/go-asn1plus.BenchmarkEncodeDirectoryString
         0     0% 91.90%         1s 27.93%  github.com/JesseCoretta/go-asn1plus.Marshal
         0     0% 91.90%      0.32s  8.94%  github.com/JesseCoretta/go-asn1plus.PrintableString.write
         0     0% 91.90%      1.21s 33.80%  github.com/JesseCoretta/go-asn1plus.Unmarshal
         0     0% 91.90%      0.47s 13.13%  github.com/JesseCoretta/go-asn1plus.adapterForValue
         0     0% 91.90%      0.07s  1.96%  github.com/JesseCoretta/go-asn1plus.getBuf (inline)
         0     0% 91.90%      0.08s  2.23%  github.com/JesseCoretta/go-asn1plus.implicitOptions (inline)
         0     0% 91.90%      0.06s  1.68%  github.com/JesseCoretta/go-asn1plus.init.func3
         0     0% 91.90%      0.04s  1.12%  github.com/JesseCoretta/go-asn1plus.init.func6
         0     0% 91.90%      0.42s 11.73%  github.com/JesseCoretta/go-asn1plus.lookupAdapter
         0     0% 91.90%      0.87s 24.30%  github.com/JesseCoretta/go-asn1plus.marshalValue
         0     0% 91.90%      0.09s  2.51%  github.com/JesseCoretta/go-asn1plus.marshalViaAdapter
         0     0% 91.90%      0.02s  0.56%  github.com/JesseCoretta/go-asn1plus.toPtr
         0     0% 91.90%      0.02s  0.56%  reflect.(*rtype).Field
         0     0% 91.90%      0.13s  3.63%  reflect.(*rtype).nameOff (inline)
         0     0% 91.90%      0.07s  1.96%  reflect.(*rtype).typeOff (inline)
         0     0% 91.90%      0.06s  1.68%  reflect.nameOffFor (inline)
         0     0% 91.90%      0.03s  0.84%  reflect.typeOffFor (inline)
         0     0% 91.90%      0.04s  1.12%  reflect.unsafe_New
         0     0% 91.90%      0.06s  1.68%  reflect.valueInterface
         0     0% 91.90%      0.05s  1.40%  runtime.(*mcache).refill
         0     0% 91.90%      0.03s  0.84%  runtime.(*mcentral).grow
         0     0% 91.90%      0.02s  0.56%  runtime.(*mcentral).uncacheSpan
         0     0% 91.90%      0.03s  0.84%  runtime.(*mheap).alloc
         0     0% 91.90%      0.03s  0.84%  runtime.(*mheap).alloc.func1
         0     0% 91.90%      0.03s  0.84%  runtime.(*mheap).allocSpan
         0     0% 91.90%      0.02s  0.56%  runtime.(*mheap).initSpan
         0     0% 91.90%      0.02s  0.56%  runtime.(*sweepLocked).sweep
         0     0% 91.90%      0.02s  0.56%  runtime.bgsweep
         0     0% 91.90%      0.03s  0.84%  runtime.convT
         0     0% 91.90%      0.03s  0.84%  runtime.efaceeq
         0     0% 91.90%      0.02s  0.56%  runtime.findRunnable
         0     0% 91.90%      0.02s  0.56%  runtime.futexsleep
         0     0% 91.90%      0.04s  1.12%  runtime.gcBgMarkWorker
         0     0% 91.90%      0.03s  0.84%  runtime.gcBgMarkWorker.func2
         0     0% 91.90%      0.03s  0.84%  runtime.gcDrain
         0     0% 91.90%      0.03s  0.84%  runtime.gcDrainMarkWorkerDedicated (inline)
         0     0% 91.90%      0.02s  0.56%  runtime.mPark (inline)
         0     0% 91.90%      0.03s  0.84%  runtime.makeslice
         0     0% 91.90%      0.02s  0.56%  runtime.mcall
         0     0% 91.90%      0.03s  0.84%  runtime.nilinterequal
         0     0% 91.90%      0.04s  1.12%  runtime.nilinterhash
         0     0% 91.90%      0.02s  0.56%  runtime.notesleep
         0     0% 91.90%      0.02s  0.56%  runtime.park_m
         0     0% 91.90%      0.05s  1.40%  runtime.rtype.typeOff (inline)
         0     0% 91.90%      0.02s  0.56%  runtime.schedule
         0     0% 91.90%      0.02s  0.56%  runtime.stopm
         0     0% 91.90%      0.02s  0.56%  runtime.sweepone
         0     0% 91.90%      0.09s  2.51%  runtime.systemstack
         0     0% 91.90%      3.49s 97.49%  testing.(*B).launch
         0     0% 91.90%      3.49s 97.49%  testing.(*B).runN
```

### Top Allocation Sites

```
$ go tool pprof -top -alloc_space mem.out

File: go-asn1plus.test
Type: alloc_space
Time: Jun 16, 2025 at 8:35pm (PDT)
Showing nodes accounting for 714.03MB, 99.41% of 718.25MB total
Dropped 27 nodes (cum <= 3.59MB)
      flat  flat%   sum%        cum   cum%
  338.02MB 47.06% 47.06%   338.02MB 47.06%  strings.(*Builder).WriteString (inline)
   56.50MB  7.87% 54.93%    56.50MB  7.87%  github.com/JesseCoretta/go-asn1plus.init.func3
      54MB  7.52% 62.45%       54MB  7.52%  github.com/JesseCoretta/go-asn1plus.init.func6
      32MB  4.46% 66.90%       32MB  4.46%  reflect.packEface
   31.50MB  4.39% 71.29%   250.01MB 34.81%  github.com/JesseCoretta/go-asn1plus.BenchmarkEncodeDirectoryString
   26.50MB  3.69% 74.98%    26.50MB  3.69%  github.com/JesseCoretta/go-asn1plus.implicitOptions (inline)
   23.50MB  3.27% 78.25%   464.02MB 64.60%  github.com/JesseCoretta/go-asn1plus.Unmarshal
   21.50MB  2.99% 81.24%   102.50MB 14.27%  github.com/JesseCoretta/go-asn1plus.EncodingRule.New
   21.50MB  2.99% 84.24%    21.50MB  2.99%  reflect.New
   18.50MB  2.58% 86.81%    18.50MB  2.58%  github.com/JesseCoretta/go-asn1plus.EncodingRule.newTLV (inline)
      18MB  2.51% 89.32%    47.50MB  6.61%  github.com/JesseCoretta/go-asn1plus.encodeTLV
   17.50MB  2.44% 91.75%   218.51MB 30.42%  github.com/JesseCoretta/go-asn1plus.Marshal
   14.50MB  2.02% 93.77%    24.50MB  3.41%  github.com/JesseCoretta/go-asn1plus.getTLV
      14MB  1.95% 95.72%       14MB  1.95%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).Append
   13.50MB  1.88% 97.60%   357.02MB 49.71%  github.com/JesseCoretta/go-asn1plus.unmarshalSequence
       9MB  1.25% 98.85%    70.50MB  9.82%  github.com/JesseCoretta/go-asn1plus.writeTLV
       4MB  0.56% 99.41%        4MB  0.56%  reflect.(*structType).Field
         0     0% 99.41%    24.50MB  3.41%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).TLV
         0     0% 99.41%   464.02MB 64.60%  github.com/JesseCoretta/go-asn1plus.BenchmarkDecodeDirectoryString
         0     0% 99.41%       79MB 11.00%  github.com/JesseCoretta/go-asn1plus.PrintableString.write
         0     0% 99.41%      155MB 21.58%  github.com/JesseCoretta/go-asn1plus.adapterForValue
         0     0% 99.41%    29.50MB  4.11%  github.com/JesseCoretta/go-asn1plus.getBuf (inline)
         0     0% 99.41%      155MB 21.58%  github.com/JesseCoretta/go-asn1plus.lookupAdapter
         0     0% 99.41%   108.50MB 15.11%  github.com/JesseCoretta/go-asn1plus.marshalPrimitive
         0     0% 99.41%   168.50MB 23.46%  github.com/JesseCoretta/go-asn1plus.marshalValue
         0     0% 99.41%       60MB  8.35%  github.com/JesseCoretta/go-asn1plus.marshalViaAdapter
         0     0% 99.41%   338.02MB 47.06%  github.com/JesseCoretta/go-asn1plus.mkerrf
         0     0% 99.41%    21.50MB  2.99%  github.com/JesseCoretta/go-asn1plus.toPtr
         0     0% 99.41%   440.52MB 61.33%  github.com/JesseCoretta/go-asn1plus.unmarshalValue
         0     0% 99.41%        4MB  0.56%  reflect.(*rtype).Field
         0     0% 99.41%       32MB  4.46%  reflect.Value.Interface (inline)
         0     0% 99.41%       32MB  4.46%  reflect.valueInterface
         0     0% 99.41%   110.50MB 15.38%  sync.(*Pool).Get
         0     0% 99.41%   714.03MB 99.41%  testing.(*B).launch
         0     0% 99.41%   714.54MB 99.48%  testing.(*B).runN
```

### 20 hottest lines by allocated bytes

```
$ go tool pprof -alloc_space -lines -nodecount=20 -top mem.out

File: go-asn1plus.test
Type: alloc_space
Time: Jun 16, 2025 at 8:35pm (PDT)
Showing nodes accounting for 707.02MB, 98.44% of 718.25MB total
Dropped 32 nodes (cum <= 3.59MB)
Showing top 20 nodes out of 62
      flat  flat%   sum%        cum   cum%
  338.02MB 47.06% 47.06%   338.02MB 47.06%  strings.(*Builder).WriteString /home/jc/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.9.linux-amd64/src/strings/builder.go:108 (inline)
   56.50MB  7.87% 54.93%    56.50MB  7.87%  github.com/JesseCoretta/go-asn1plus.init.func3 /home/jc/dev/go-asn1plus/der.go:208
      54MB  7.52% 62.45%       54MB  7.52%  github.com/JesseCoretta/go-asn1plus.init.func6 /home/jc/dev/go-asn1plus/pkt.go:429
      32MB  4.46% 66.90%       32MB  4.46%  reflect.packEface /home/jc/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.9.linux-amd64/src/reflect/value.go:135
   31.50MB  4.39% 71.29%   250.01MB 34.81%  github.com/JesseCoretta/go-asn1plus.BenchmarkEncodeDirectoryString /home/jc/dev/go-asn1plus/pkt_test.go:798
   26.50MB  3.69% 74.98%    26.50MB  3.69%  github.com/JesseCoretta/go-asn1plus.implicitOptions /home/jc/dev/go-asn1plus/opts.go:60 (inline)
   21.50MB  2.99% 77.97%    21.50MB  2.99%  reflect.New /home/jc/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.9.linux-amd64/src/reflect/value.go:3322
   18.50MB  2.58% 80.55%    18.50MB  2.58%  github.com/JesseCoretta/go-asn1plus.EncodingRule.newTLV /home/jc/dev/go-asn1plus/er.go:83 (inline)
   17.50MB  2.44% 82.98%    17.50MB  2.44%  github.com/JesseCoretta/go-asn1plus.Marshal /home/jc/dev/go-asn1plus/runtime.go:26
      14MB  1.95% 84.93%       14MB  1.95%  github.com/JesseCoretta/go-asn1plus.(*DERPacket).Append /home/jc/dev/go-asn1plus/der.go:111
      12MB  1.67% 86.60%       12MB  1.67%  github.com/JesseCoretta/go-asn1plus.EncodingRule.New /home/jc/dev/go-asn1plus/er.go:54
      12MB  1.67% 88.27%       12MB  1.67%  github.com/JesseCoretta/go-asn1plus.Unmarshal /home/jc/dev/go-asn1plus/runtime.go:233
   11.50MB  1.60% 89.87%    11.50MB  1.60%  github.com/JesseCoretta/go-asn1plus.Unmarshal /home/jc/dev/go-asn1plus/runtime.go:231
   11.50MB  1.60% 91.48%    11.50MB  1.60%  github.com/JesseCoretta/go-asn1plus.getTLV /home/jc/dev/go-asn1plus/tlv.go:153
      11MB  1.53% 93.01%       11MB  1.53%  github.com/JesseCoretta/go-asn1plus.encodeTLV /home/jc/dev/go-asn1plus/tlv.go:127
    9.50MB  1.32% 94.33%     9.50MB  1.32%  github.com/JesseCoretta/go-asn1plus.EncodingRule.New /home/jc/dev/go-asn1plus/er.go:65
    9.50MB  1.32% 95.65%     9.50MB  1.32%  github.com/JesseCoretta/go-asn1plus.unmarshalSequence /home/jc/dev/go-asn1plus/seq.go:164
       9MB  1.25% 96.91%        9MB  1.25%  github.com/JesseCoretta/go-asn1plus.writeTLV /home/jc/dev/go-asn1plus/tlv.go:202
       7MB  0.97% 97.88%        7MB  0.97%  github.com/JesseCoretta/go-asn1plus.encodeTLV /home/jc/dev/go-asn1plus/tlv.go:110
       4MB  0.56% 98.44%        4MB  0.56%  github.com/JesseCoretta/go-asn1plus.unmarshalSequence /home/jc/dev/go-asn1plus/seq.go:162
```

# Test Binary Size

```
$ go test -c -o pkg.test

size pkg.test
   text	   data	    bss	    dec	    hex	filename
5500643	 138720	 191136	5830499	 58f763	pkg.test
```

