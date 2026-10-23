package query

import (
	"net/http"
	"strings"

	"github.com/smck83/phparmor/internal/policy"
)

// Limits are the PA-QUERY limits (SPEC section 5.3).
type Limits struct {
	Seps         string // php.arg_separator_input
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
// combined counting with the body) and a violation, if any. The query
// itself is never modified. Percent-encoding is checked leniently, as PHP
// decodes it.
func Check(raw string, l Limits) (pairs int, v *policy.Violation) {
	if int64(len(raw)) > l.MaxLength {
		return 0, &policy.Violation{Reason: ReasonTooLong, Status: http.StatusRequestURITooLong}
	}
	res, _ := Scan(strings.NewReader(raw), ScanLimits{
		Seps: l.Seps, MaxVars: l.MaxVars, MaxNesting: l.MaxNesting, MaxKeyLength: l.MaxKeyLength,
	}, nil)
	if res.Reason != "" {
		return res.Pairs, &policy.Violation{Reason: res.Reason, Status: http.StatusBadRequest}
	}
	return res.Pairs, nil
}
