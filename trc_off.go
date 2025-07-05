//go:build !asn1_debug

package asn1plus

type DefaultTracer struct{}
type labeledItem struct{}

func debugEnter(_ ...any)                  {}
func debugExit(_ ...any)                   {}
func debugEvent(_ EventType, _ ...any)     {}
func debugInfo(_ ...any)                   {}
func debugIO(_ ...any)                     {}
func debugTLV(_ ...any)                    {}
func debugPDU(_ ...any)                    {}
func debugConstraint(_ ...any)             {}
func debugAdapter(_ ...any)                {}
func debugPrim(_ ...any)                   {}
func debugPerf(_ ...any)                   {}
func debugChoice(_ ...any)                 {}
func debugTrace(_ ...any)                  {}
func debugSeqSet(_ ...any)                 {}
func debugCodec(_ ...any)                  {}
func debugPath(_ ...any) func(_ ...any)    { return func(_ ...any) {} }
func makePacketID() string                 { return "" }
func newLItem(_ any, _ ...any) labeledItem { return labeledItem{} }
func (_ labeledItem) String() string       { return `` }
