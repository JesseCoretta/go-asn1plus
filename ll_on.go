//go:build asn1_debug

package asn1plus

type loglevels struct {
	v *uint16
	m map[int]string
}

func newLoglevels() (bv loglevels) {
	bv.v = new(uint16)
	return
}

func (r loglevels) enabled() (names []string) {
	if (*r.v) == 0 {
		names = []string{"none"}
		return
	} else if (*r.v) == 65535 {
		names = []string{"all"}
		return
	}

	for i := 0; i < 16; i++ {
		d := 1 << i
		if (*r.v)&uint16(d) != 0 {
			names = append(names, r.m[d])
		}
	}

	return
}

func (r loglevels) NamesMap() map[int]string {
	return r.m
}

func (r *loglevels) SetNamesMap(m map[int]string) {
	r.m = m
}

func (r loglevels) Int() int {
	var i int
	if r.v != nil {
		i = int(*r.v)
	}
	return i
}

func (r *loglevels) Shift(x ...any) loglevels {
	for _, xi := range x {
		if X, ok := r.verifyShiftValue(xi); ok {
			r.shift(X)
		}
	}
	return *r
}

func (r loglevels) None() loglevels {
	return r.Unshift(r.Max())
}

func (r *loglevels) All() loglevels {
	r.Shift(r.Max())
	return *r
}

func (r *loglevels) Unshift(x ...any) loglevels {
	for _, xi := range x {
		if X, ok := r.verifyShiftValue(xi); ok {
			r.unshift(X)
		}
	}
	return *r
}

func (r loglevels) Positive(x any) bool {
	if X, ok := r.verifyShiftValue(x); ok {
		return r.positive(X)
	}
	return false
}

func (r *loglevels) shift(x int) {
	if r.v != nil {
		if r.isExtreme(x) {
			r.shiftExtremes(x)
			return
		}
		if !r.positive(x) {
			*r.v |= uint16(x)
		}
	}
}

func (r loglevels) isExtreme(x int) bool {
	return x == r.Max() || x == 0
}

func (r loglevels) shiftExtremes(x int) {
	if x == r.Max() {
		*r.v = ^uint16(0)
	}
}

func (r *loglevels) unshift(x int) {
	if r != nil {
		if r.isExtreme(x) {
			r.unshiftExtremes(x)
			return
		}
		if r.positive(x) {
			*r.v &^= uint16(x)
		}
	}
}

func (r loglevels) unshiftExtremes(x int) {
	if x == r.Max() {
		*r.v = 0
	}
}

func (r loglevels) positive(x int) (posi bool) {
	if r.v != nil {
		posi = (*r.v)&uint16(x) != 0
	}
	return
}

func toLogInt(x any) (v int, ok bool) {
	switch tv := x.(type) {
	case int:
		return tv, true
	case uint8:
		return int(tv), true
	case uint16:
		return int(tv), true
	}
	return 0, false
}

func (r loglevels) Max() int { return int(^uint16(0)) }

func (r loglevels) Min() int { return 0 }

func (r loglevels) verifyShiftValue(x any) (int, bool) {
	if str, isStr := x.(string); isStr {
		x = r.strIndex(str)
	}
	if X, ok := toLogInt(x); ok && X >= r.Min() && X <= r.Max() {
		return X, true
	}
	return 0, false
}

func (r loglevels) strIndex(name string) int {
	for k, v := range r.m {
		if streqf(v, name) {
			return k
		}
	}
	return -1
}
