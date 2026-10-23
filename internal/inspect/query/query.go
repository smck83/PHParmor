package query

import (
	"net/http"

	"github.com/smck83/phparmor/internal/policy"
)

// Limits are the PA-QUERY limits (SPEC section 5.3).
type Limits struct {
	MaxVars      int
	MaxNesting   int
	MaxKeyLength int
	MaxLength    int64
}

// Violation reasons. These appear in logs and decision records.
const (
	ReasonTooLong     = "query_too_long"
	ReasonTooManyVars = "too_many_vars"
	ReasonTooDeep     = "nesting_too_deep"
	ReasonKeyTooLong  = "key_too_long"
)

// Check validates a raw query string. It returns the variable count (for
// combined counting with the body in M4) and a violation, if any. The query
// itself is never modified.
func Check(raw string, l Limits) (pairs int, v *policy.Violation) {
	if int64(len(raw)) > l.MaxLength {
		return 0, &policy.Violation{Reason: ReasonTooLong, Status: http.StatusRequestURITooLong}
	}
	r := Parse(raw, '&')
	return r.Pairs, CheckVars(r, l)
}

// CheckVars applies the count, nesting and key-length limits to a parsed
// variable string.
func CheckVars(r Result, l Limits) *policy.Violation {
	if r.Pairs > l.MaxVars {
		return &policy.Violation{Reason: ReasonTooManyVars, Status: http.StatusBadRequest}
	}
	for _, v := range r.Vars {
		if v.Depth > l.MaxNesting {
			return &policy.Violation{Reason: ReasonTooDeep, Status: http.StatusBadRequest}
		}
		if len(v.Key) > l.MaxKeyLength {
			return &policy.Violation{Reason: ReasonKeyTooLong, Status: http.StatusBadRequest}
		}
	}
	return nil
}
