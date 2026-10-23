// Package urlenc implements PA-URLENC: validation of
// application/x-www-form-urlencoded bodies as PHP will parse them into
// $_POST (SPEC section 5.4). The body is only validated; its original bytes
// are always forwarded.
package urlenc

import (
	"io"
	"net/http"

	"github.com/smck83/phparmor/internal/inspect/query"
	"github.com/smck83/phparmor/internal/policy"
)

// Limits apply to one urlencoded body.
type Limits struct {
	Seps string // php.arg_separator_input
	// MaxVars is max_vars minus the query string's variables: PHParmor
	// counts query and body variables against one combined cap.
	MaxVars        int
	MaxNesting     int
	MaxKeyLength   int
	MaxValueLength int64
	// UploadProgressField is php.upload_progress_field.
	UploadProgressField string
}

// Result describes a scanned body.
type Result struct {
	Pairs int
	// UploadProgress is set when a variable named like the upload-progress
	// field was seen. The caller applies PA-UPROG.
	UploadProgress bool
}

// Check scans a urlencoded body and returns the first PA-URLENC violation,
// if any. err is non-nil only for read errors.
func Check(r io.Reader, l Limits) (Result, *policy.Violation, error) {
	var out Result
	watch := progressMatcher(l.UploadProgressField)
	res, err := query.Scan(r, query.ScanLimits{
		Seps:           l.Seps,
		MaxVars:        l.MaxVars,
		MaxNesting:     l.MaxNesting,
		MaxKeyLength:   l.MaxKeyLength,
		MaxValueLength: l.MaxValueLength,
		StrictPercent:  true,
	}, func(v query.Var) {
		if watch(v) {
			out.UploadProgress = true
		}
	})
	out.Pairs = res.Pairs
	if err != nil {
		return out, nil, err
	}
	return out, violation(res.Reason), nil
}

// HasUploadProgress scans the whole body, with no limits, for a variable
// named like the upload-progress field. PA-UPROG uses it when Check stopped
// early at a violation that is not being enforced.
func HasUploadProgress(r io.Reader, seps, field string) (bool, error) {
	watch := progressMatcher(field)
	found := false
	res, err := query.Scan(r, query.ScanLimits{
		Seps: seps, MaxVars: int(^uint(0) >> 1), MaxNesting: int(^uint(0) >> 1), MaxKeyLength: 1 << 16,
	}, func(v query.Var) {
		if watch(v) {
			found = true
		}
	})
	// A key too long to hold stops the scan; the rest is unchecked, so
	// fail closed.
	return found || res.Reason != "", err
}

func progressMatcher(field string) func(query.Var) bool {
	if field == "" {
		return func(query.Var) bool { return false }
	}
	base := ""
	if v, ok := query.Register(field); ok {
		base = v.Base
	}
	return func(v query.Var) bool { return v.Key == field || v.Base == base }
}

func violation(reason string) *policy.Violation {
	switch reason {
	case "":
		return nil
	case query.ReasonTooManyVars, query.ReasonValueTooLarge:
		return &policy.Violation{Reason: reason, Status: http.StatusRequestEntityTooLarge}
	default:
		return &policy.Violation{Reason: reason, Status: http.StatusBadRequest}
	}
}
