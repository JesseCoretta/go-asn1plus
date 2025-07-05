//go:build asn1_debug

package asn1plus

import (
	"io"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"
)

/*
EnvDebugVar defines the environment variable name which can
be leveraged to invoke or disable use of the [DefaultTracer]
[Tracer] qualifier.

Use sparingly in high-volume/performance-sensitive scenarios.
*/
const EnvDebugVar = "ASN1PLUS_DEBUG"

const coreTracerMask = EventEnter | EventInfo | EventExit

/*
DefaultTracer is the package-level [Tracer] implementation.
*/
type DefaultTracer struct {
	mu sync.Mutex
	w  io.Writer
	ll loglevels
}

/*
NewDefaultTracer returns an instance of *[DefaultTracer]. The
input [io.Writer] value represents the writer interface type
to which debug data shall be written.
*/
func NewDefaultTracer(writer io.Writer) *DefaultTracer {
	return &DefaultTracer{
		mu: sync.Mutex{},
		w:  writer,
		ll: newLoglevels(),
	}
}

/*
EnableLevel adds [EventType] ev to the collection of loglevels
to be used during debugging.

Note that this method can be used to override any such loglevels
activated via the [EnvDebugVar] environment variable at runtime.
*/
func (r *DefaultTracer) EnableLevel(ev EventType) { r.ll.Shift(int(ev)) }

/*
DisableLevel removes [EventType] ev from the collection of loglevels
to be used during debugging.

Note that this method can be used to override any such loglevels
activated via the [EnvDebugVar] environment variable at runtime.
*/
func (r *DefaultTracer) DisableLevel(ev EventType) { r.ll.Unshift(int(ev)) }

/*
Trace writes [TraceRecord] rec to the [io.Writer] handled by the
receiver instance. This method need not be executed by the end
user directly.
*/
func (r *DefaultTracer) Trace(rec TraceRecord) {
	// drop if any bit in rec.Type isn't enabled
	if !r.ll.Positive(int(rec.Type)) {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	ts := rec.Time.Format("15:04:05.000")
	fn := trimFuncName(rec.Func)

	switch rec.Type & coreTracerMask {
	case EventEnter:
		r.writeEnter(ts, fn, rec.Args)
	case EventExit:
		r.writeExit(ts, fn, rec.Ret)
	default:
		r.writeInfo(ts, fn, rec.Args)
	}
}

/*
Enabled returns a Boolean value indicative of the specified
[EventType] being enabled within the receiver instance.
*/
func (r *DefaultTracer) Enabled(e EventType) bool {
	return r.ll.Positive(int(e))
}

func trimFuncName(full string) string {
	if i := lidx(full, "/"); i >= 0 {
		return full[i+1:]
	}
	return full
}

func (r *DefaultTracer) writeEnter(ts, fn string, args []any) {
	r.w.Write([]byte(ts + " → " + fn + "("))
	for i, a := range args {
		if i > 0 {
			r.w.Write([]byte(", "))
		}
		if s := fmtArg(a); s != "" {
			r.w.Write([]byte(s))
		}
	}
	r.w.Write([]byte(")\n"))
}

func (r *DefaultTracer) writeInfo(ts, fn string, args []any) {
	r.w.Write([]byte(ts + "     • " + fn + ": "))
	for i, a := range args {
		if i > 0 {
			r.w.Write([]byte(", "))
		}
		if s := fmtArg(a); s != "" {
			r.w.Write([]byte(s))
		}
	}
	r.w.Write([]byte("\n"))
}

func (r *DefaultTracer) writeExit(ts, fn string, rets []any) {
	r.w.Write([]byte(ts + " ← " + fn + " => "))
	for i, a := range rets {
		if i > 0 {
			r.w.Write([]byte(", "))
		}
		if s := fmtArg(a); s != "" {
			r.w.Write([]byte(s))
		}
	}
	r.w.Write([]byte("\n"))
}

/*
TraceRecord encapsulates metadata pertaining to a particular event
observed by a [Tracer]. This includes a [time.Time] timestamp, an
[EventType] as well as in/out arguments.
*/
type TraceRecord struct {
	Time  time.Time // timestamp, i.e.: time.Now()
	Type  EventType // Enter, Info or Exit
	Func  string    // FuncName -or- TypeName.MethodName
	Depth int       // Nesting depth
	Args  []any     // On Enter: parameters
	Ret   []any     // On Exit: return values (last entry may be error)
}

/*
Tracer implements an interface tracer type, which is implemented
by [DefaultTracer].
*/
type Tracer interface {
	Trace(TraceRecord)
}

type levelTracer interface {
	Tracer
	Enabled(EventType) bool
}

/*
EnableDebug registers and activates [Tracer] for debugging.

This function need not be called if an environment variable of
[EnvDebugVar] was read and successfully parsed at runtime.
*/
func EnableDebug(t Tracer) {
	tmu.Lock()
	defer tmu.Unlock()
	tracer = t
}

/*
DisableDebug disables [Tracer] debugging.
*/
func DisableDebug() {
	tmu.Lock()
	defer tmu.Unlock()
	tracer = &discardTracer{}
}

var (
	tmu    sync.RWMutex
	tracer Tracer = &discardTracer{} // default
)

type discardTracer struct{}

func (*discardTracer) Trace(_ TraceRecord)      {}
func (*discardTracer) Enabled(_ EventType) bool { return false }

var (
	rndMu       sync.Mutex
	rnd         = rand.New(rand.NewSource(tnow().UnixNano()))
	packetIDLen = 16
)

func makePacketID() string {
	buf := make([]byte, packetIDLen)
	rndMu.Lock()
	for i := range buf {
		buf[i] = hexDigits[rnd.Intn(16)]
	}
	rndMu.Unlock()
	return string(buf)
}

func debugEvent(level EventType, args ...any) {
	tmu.RLock()
	t := tracer
	tmu.RUnlock()

	lt, ok := t.(levelTracer)
	if ok {
		if !(lt.Enabled(level) || lt.Enabled(EventAll)) {
			return
		}
	}

	// now fire the record
	pc, _, _, ok := runtime.Caller(2)
	fn := callerName()

	if ok {
		fn = runtime.FuncForPC(pc).Name()
	}
	fn = replaceAll(fn, "go-asn1plus.", "")
	if cntns(fn, ".func") {
		fn = fn[:lidx(fn, ".")]
	}
	rec := TraceRecord{
		Time: tnow(),
		Type: level,
		Func: fn,
	}
	if lt.Enabled(EventIO) {
		if len(args) == 0 {
			args = []any{"no values"}
		}
		if level == EventExit {
			rec.Ret = args
		} else {
			rec.Args = args
		}
	}
	t.Trace(rec)
}

func callerName() string {
	// skip: runtime.Callers(0), callerName(1), traceEvent(2)
	pcs := make([]uintptr, 10)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	for {
		fr, more := frames.Next()
		name := fr.Function
		if !hasPfx(name, "debug") {
			return name
		}
		if !more {
			break
		}
	}
	return "unknown"
}

func debugPath(args ...any) func(rets ...any) {
	debugEvent(EventEnter, args...)
	return func(rets ...any) {
		debugEvent(EventExit, rets...)
	}
}

func debugInfo(input ...any)      { debugEvent(EventInfo, input...) }
func debugIO(args ...any)         { debugEvent(EventIO, args...) }
func debugPDU(args ...any)        { debugEvent(EventPDU, args...) }
func debugTLV(args ...any)        { debugEvent(EventTLV, args...) }
func debugPerf(args ...any)       { debugEvent(EventPerf, args...) }
func debugConstraint(args ...any) { debugEvent(EventConstraint, args...) }
func debugSeqSet(args ...any)     { debugEvent(EventSeqSet, args...) }
func debugPrim(args ...any)       { debugEvent(EventPrim, args...) }
func debugChoice(args ...any)     { debugEvent(EventChoice, args...) }
func debugAdapter(args ...any)    { debugEvent(EventAdapter, args...) }
func debugTrace(args ...any)      { debugEvent(EventTrace, args...) }
func debugCodec(args ...any)      { debugEvent(EventCodec, args...) }
func debugEnter(args ...any)      { debugEvent(EventEnter, args...) }
func debugExit(args ...any)       { debugEvent(EventExit, args...) }

// strictly for debugging.
type labeledItem struct {
	L string
	V any
}

func newLItem(value any, labels ...any) (li labeledItem) {
	li = labeledItem{V: value}
	var l []string
	for i := 0; i < len(labels); i++ {
		switch tv := labels[i].(type) {
		case EncodingRule:
			l = append(l, tv.String())
		case string:
			l = append(l, tv)
		}
	}

	li.L = join(l, ` `)

	return
}

func (r labeledItem) String() string {
	var l = "<No label>:"
	var v = "<Nil value>"
	if err, is := r.V.(error); is {
		if r.L == "" {
			l = "Error:"
		} else {
			l = r.L + ":"
		}
		if err != nil {
			v = l + v
		} else {
			v = l + "<Nil error>"
		}
	} else {
		if r.L != "" {
			l = r.L + ":"
		}
		_v := ""
		if pkt, is := r.V.(PDU); is {
			// Just provide the PDU summary
			_v = "[" + pkt.Type().String() + ":" + pkt.ID() +
				",len:" + itoa(pkt.Len()) + ",off:" + itoa(pkt.Offset()) + "]"
		} else if tlv, is := r.V.(TLV); is {
			_v = "[type:" + tlv.Type().String() + ",class:" + itoa(tlv.Class) +
				",tag:" + itoa(tlv.Tag) + ",compound:" + bool2str(tlv.Compound) +
				",len:" + itoa(tlv.Length) + "]"
		} else {
			_v = fmtArg(r.V)
		}
		if _v != "" {
			v = _v
		}
		v = l + v
	}

	return v
}

func fmtArg(x interface{}) (s string) {
	switch v := x.(type) {
	case int, []int:
		s = fmtIntArg(v)
	case string:
		s = v
	case bool:
		s = bool2str(v)
	case byte, []byte:
		s = fmtByteSliceArg(v)
	case reflect.Type, reflect.Value:
		s = fmtReflectionArg(v)
	case labeledItem:
		s = v.String()
	case Options, *Options:
		s = fmtOptionsArg(v)
	case []EncodingOption:
		s = fmtEncOptArg(v)
	case codecRW:
		s = refTypeOf(v).String()
	case Primitive:
		s = fmtPrimitiveArg(v)
	case EncodingRule:
		s = v.String()
	case TLV:
		s = "TLV: " + v.String()
	case PDU:
		s = fmtPDUArg(v)
	default:
		s = fmtDefaultArg(v)
	}

	return
}

func fmtIntArg(x any) string {
	var v []int
	switch tv := x.(type) {
	case int:
		v = append(v, tv)
	case []int:
		v = tv
	}

	var strs []string
	for i := 0; i < len(v); i++ {
		strs = append(strs, itoa(v[i]))
	}
	return join(strs, ` `)
}

func fmtEncOptArg(x []EncodingOption) string {
	var _s []string
	for i := 0; i < len(x); i++ {
		_s = append(_s, fmtArg(x[i]))
	}
	return join(_s, " ")
}

func fmtReflectionArg(x any) (s string) {
	switch v := x.(type) {
	case reflect.Type:
		s = `reflect.Type:` + v.String()
	case reflect.Value:
		s = `reflect.Value:` + v.Type().String()
	}

	return
}

func fmtByteSliceArg(x any) (s string) {
	var v []byte
	switch tv := x.(type) {
	case byte:
		v = append(v, tv)
	case []byte:
		v = tv
	}

	var strs []string
	for i := 0; i < len(v); i++ {
		strs = append(strs, fmtUint(uint64(v[i]), 8))
	}
	s = join(strs, ` `)
	return
}

func fmtOptionsArg(x any) (s string) {
	switch v := x.(type) {
	case *Options:
		s = `<Empty Options>`
		if v != nil {
			s = v.String()
		}
	case Options:
		s = fmtOptionsArg(&v)
	}

	return
}

func fmtPrimitiveArg(v Primitive) (s string) {
	s = "<Unidentified ASN.1 PRIMITIVE>"
	if tname, found := TagNames[v.Tag()]; found {
		s = tname
	}
	s += " " + v.String() + " (tag:" + itoa(v.Tag()) + ")"
	return
}

func fmtDefaultArg(v any) (s string) {
	s = "<Unidentified>"
	if v != nil {
		rt := refTypeOf(v)
		if rt.Kind() == 25 {
			s = "STRUCT (" + rt.String() + ")"
		} else if rt.Kind() == 23 {
			s = "SLICE (" + rt.String() + ")"
		} else {
			s = rt.String()
		}
		if meth, found := getTagMethod(v); found {
			s += " (tag:" + itoa(meth()) + ")"
		}
	}

	return s
}

func fmtPDUArg(v PDU) (s string) {
	s = "<Nil PDU>"
	if v != nil {
		tmu.RLock()
		t := tracer
		tmu.RUnlock()
		lt, ok := t.(levelTracer)
		ok = lt.Enabled(EventPDU) && ok
		s = v.Type().String() + " PACKET"
		off := "[OFF:" + itoa(v.Offset()) + ", LEN:" + itoa(v.Len()) + "]"
		if ok {
			b := newStrBuilder()
			if v.Len() > 0 {
				v.Dump(&b)
				s += " DUMP " + off + ":\n" + b.String()
			} else {
				s += " <empty, initialized>"
			}
		} else {
			s += " " + off
		}
	}

	return s
}

func init() {
	if evar := os.Getenv(EnvDebugVar); evar != "" {
		sp := split(evar, ",")
		var vars []any
		for i := 0; i < len(sp); i++ {
			if n, err := atoi(sp[i]); err != nil {
				sp[i] = lc(sp[i])
				if sp[i] == "sequence" || sp[i] == "set" {
					sp[i] = "seq/set"
				}
				vars = append(vars, sp[i])
			} else if n <= 65535 {
				if n < 0 {
					vars = []any{int(EventAll)}
					break
				}
				vars = append(vars, n)
			}
		}

		ll := newLoglevels()
		ll.SetNamesMap(map[int]string{
			int(EventAll):        "all",
			int(EventNone):       "none",
			int(EventEnter):      "enter",
			int(EventInfo):       "info",
			int(EventExit):       "exit",
			int(EventChoice):     "choice",
			int(EventSeqSet):     "seq/set",
			int(EventAdapter):    "adapter",
			int(EventTrace):      "trace",
			int(EventPDU):        "pdu",
			int(EventConstraint): "constraint",
			int(EventPrim):       "primitive",
			int(EventTLV):        "tlv",
			int(EventPerf):       "perf",
			int(EventIO):         "io",
		})

		ll.Shift(vars...)

		dt := NewDefaultTracer(os.Stderr)
		dt.ll = ll
		EnableDebug(dt)
		debugInfo(newLItem(join(ll.enabled(), `,`), "loglevels"))
	}
}
