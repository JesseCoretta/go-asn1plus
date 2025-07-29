package asn1plus

/*
evt.go contains EventType constants which are (only) used
for debugging when this package was built or run with the
"-tags asn1_debug" flag.
*/

/*
EventType describes a specific kind of [Tracer] event. see the
[EventType] constants for a full list and descriptions.

Note that this type and all of its constants are only meaningful
if/when this package was run or built with the "-tags asn1_debug"
flag. Otherwise, they can be ignored entirely.
*/
type EventType int

const (
	EventNone EventType = 0     // NO events
	EventAll  EventType = 65535 // ALL events (use with extreme caution)
)

const (
	EventEnter      EventType = 1 << iota //     1: Called-function begin
	EventInfo                             //     2: Interim function event
	EventExit                             //     4: Called function exit
	EventIO                               //     8: Called function inputs/outputs
	EventPDU                              //    16: Deep-level PDU analysis
	EventTLV                              //    32: TLV ops
	EventPerf                             //    64: Timing/microbenchmarks
	EventComposite                        //   128: SEQUENCE/SET recursion
	EventPrim                             //   256: ASN.1 PRIMITIVE ops
	EventChoice                           //   512: ASN.1 CHOICE ops
	EventAdapter                          //  1024: Adapter ops
	EventConstraint                       //  2048: Constraint ops
	EventTrace                            //  4096: Low-level ops; allocs, pools, appends, locks, et al.
	EventCodec                            //  8192: Encoding/decoding operations
	_                                     // 16384: unassigned
	_                                     // 32768: unassigned
)
