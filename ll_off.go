//go:build !asn1_debug

package asn1plus

type loglevels struct{}

func toLogInt(_ any) (int, bool)                       { return 0, false }
func newLoglevels() (_ loglevels)                      { return loglevels{} }
func (_ loglevels) NamesMap() map[int]string           { return nil }
func (_ *loglevels) SetNamesMap(_ map[int]string)      {}
func (_ loglevels) Int() int                           { return 0 }
func (_ *loglevels) Shift(_ ...any) loglevels          { return loglevels{} }
func (_ loglevels) None() loglevels                    { return loglevels{} }
func (_ *loglevels) All() loglevels                    { return loglevels{} }
func (_ *loglevels) Unshift(_ ...any) loglevels        { return loglevels{} }
func (_ loglevels) Positive(_ any) bool                { return false }
func (_ *loglevels) shift(_ int)                       {}
func (_ loglevels) isExtreme(_ int) bool               { return false }
func (_ loglevels) shiftExtremes(_ int)                {}
func (_ *loglevels) unshift(_ int)                     {}
func (_ loglevels) unshiftExtremes(_ int)              {}
func (_ loglevels) positive(_ int) bool                { return false }
func (_ loglevels) Max() int                           { return 0 }
func (_ loglevels) Min() int                           { return 0 }
func (_ loglevels) verifyShiftValue(_ any) (int, bool) { return 0, false }
func (_ loglevels) strIndex(_ string) int              { return 0 }
func (_ loglevels) enabled() []string                  { return nil }
