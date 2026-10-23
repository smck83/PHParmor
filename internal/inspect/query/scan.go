package query

import (
	"errors"
	"io"
	"strings"
)

// Scan reasons. Callers map them to statuses.
const (
	ReasonBadPercent    = "invalid_percent_encoding"
	ReasonValueTooLarge = "value_too_large"
)

// ScanLimits bound a streamed variable string. Zero MaxValueLength means no
// value limit.
type ScanLimits struct {
	Seps           string // separator bytes (php.arg_separator_input)
	MaxVars        int
	MaxNesting     int
	MaxKeyLength   int
	MaxValueLength int64
	// StrictPercent rejects any '%' not followed by two hex digits.
	StrictPercent bool
}

// ScanResult is the outcome of Scan. Reason is the first violation, or "".
type ScanResult struct {
	Pairs  int
	Reason string
}

// Scan reads a PHP variable string (query string or urlencoded body) from r
// and applies the limits the way PHP will see the variables, stopping at
// the first violation. onVar, if not nil, is called for each variable PHP
// would register. Memory use is bounded by MaxKeyLength: values are never
// held, and a raw key longer than 3*MaxKeyLength bytes is rejected without
// being kept (it must decode to more than MaxKeyLength bytes).
func Scan(r io.Reader, l ScanLimits, onVar func(Var)) (ScanResult, error) {
	s := scanner{l: l, onVar: onVar, maxRawKey: 3 * l.MaxKeyLength}
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			if s.byte(c) {
				return s.res, nil
			}
		}
		if errors.Is(err, io.EOF) {
			s.endSegment()
			return s.res, nil
		}
		if err != nil {
			return s.res, err
		}
	}
}

type scanner struct {
	l         ScanLimits
	onVar     func(Var)
	res       ScanResult
	maxRawKey int

	key         []byte
	keyOverflow bool
	inValue     bool
	segLen      int
	valueLen    int64
	pct         int // hex digits still expected after '%'
}

// byte consumes one byte and reports whether scanning must stop.
func (s *scanner) byte(c byte) bool {
	if strings.IndexByte(s.l.Seps, c) >= 0 {
		return s.endSegment()
	}
	s.segLen++

	counts := true // whether c adds a decoded byte
	switch {
	case s.pct > 0 && isHex(c):
		s.pct--
		counts = false
	case s.pct > 0 && s.l.StrictPercent:
		return s.fail(ReasonBadPercent)
	default:
		// A broken escape is kept literally by PHP; a '%' here starts
		// a new one.
		s.pct = 0
		if c == '%' {
			s.pct = 2
		}
	}

	if !s.inValue {
		if c == '=' {
			s.inValue = true
			return false
		}
		if len(s.key) < s.maxRawKey {
			s.key = append(s.key, c)
		} else {
			s.keyOverflow = true
		}
		return false
	}
	if counts {
		s.valueLen++
		if s.l.MaxValueLength > 0 && s.valueLen > s.l.MaxValueLength {
			return s.fail(ReasonValueTooLarge)
		}
	}
	return false
}

// endSegment finishes the current name=value pair and reports whether
// scanning must stop.
func (s *scanner) endSegment() bool {
	defer s.reset()
	if s.pct > 0 && s.l.StrictPercent {
		return s.fail(ReasonBadPercent)
	}
	if s.segLen == 0 {
		return false // PHP skips empty segments
	}
	s.res.Pairs++
	if s.res.Pairs > s.l.MaxVars {
		return s.fail(ReasonTooManyVars)
	}
	if s.keyOverflow {
		return s.fail(ReasonKeyTooLong)
	}
	v, ok := Register(Decode(string(s.key)))
	if !ok {
		return false
	}
	if v.Depth > s.l.MaxNesting {
		return s.fail(ReasonTooDeep)
	}
	if len(v.Key) > s.l.MaxKeyLength {
		return s.fail(ReasonKeyTooLong)
	}
	if s.onVar != nil {
		s.onVar(v)
	}
	return false
}

func (s *scanner) fail(reason string) bool {
	s.res.Reason = reason
	return true
}

func (s *scanner) reset() {
	s.key = s.key[:0]
	s.keyOverflow, s.inValue = false, false
	s.segLen, s.valueLen, s.pct = 0, 0, 0
}
