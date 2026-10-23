package server

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/smck83/phparmor/internal/config"
	"github.com/smck83/phparmor/internal/inspect/ctype"
	"github.com/smck83/phparmor/internal/inspect/multipart"
	"github.com/smck83/phparmor/internal/inspect/query"
	"github.com/smck83/phparmor/internal/inspect/urlenc"
	"github.com/smck83/phparmor/internal/policy"
	"github.com/smck83/phparmor/internal/spool"
	"github.com/smck83/phparmor/internal/telemetry"
)

// partOverhead bounds the bytes the canonical writer adds per part beyond
// the part data (boundary line, rebuilt headers at their maximum sizes).
const partOverhead = 1024

// prepareBody reads the request body into the spool and swaps it into r
// with an exact Content-Length (SPEC section 4, step 7):
//
//   - multipart/form-data with PA-MPART enforced is canonicalised while it
//     streams in (SPEC section 6), and PA-UPROG is applied to the result;
//   - with PA-MPART in monitor or off, the original bytes are spooled,
//     inspected for PA-MPART and PA-UPROG decisions, and forwarded unchanged;
//   - any other body is spooled under the route's size cap.
//
// It returns the body to close once the response is done (nil-safe), and
// true when the request was rejected.
func (s *Server) prepareBody(w http.ResponseWriter, r *http.Request, ri *telemetry.RequestInfo, cfg *config.Config, route *policy.Route) (*spool.Body, bool) {
	if r.ContentLength == 0 {
		return nil, false
	}
	lim := route.Limits
	max := int64(lim.MaxBody)
	if r.ContentLength > max {
		s.reject(w, ri, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, true
	}

	ct := r.Header.Get("Content-Type")
	media := ctype.PHPMediaType(ct)
	isMultipart := media == ctype.Multipart
	if isMultipart && route.Multipart == "deny" {
		if s.control(w, ri, route, config.CtlRouteMPart, func() *policy.Violation {
			return &policy.Violation{Reason: "multipart_not_allowed", Status: http.StatusForbidden}
		}) {
			return nil, true
		}
	}

	src := newClientReader(w, r.Body, cfg, max)
	defer src.done()
	mpartMode, uprogMode := route.Mode(config.CtlMPart), route.Mode(config.CtlUProg)
	remainingVars := bodyVarBudget(cfg, lim, r.URL.RawQuery)
	mlimits := multipartLimits(cfg, lim, remainingVars)

	if isMultipart && mpartMode == config.ModeEnforce {
		boundary, why := multipart.Boundary(ct)
		if why != "" {
			s.control(w, ri, route, config.CtlMPart, func() *policy.Violation {
				return &policy.Violation{Reason: why, Status: http.StatusBadRequest}
			})
			return nil, true
		}
		nb := multipart.NewBoundary()
		body := s.pool.NewBody(max + int64(lim.MaxParts+1)*partOverhead)
		res, v, err := multipart.Canonicalize(src, boundary, nb, body, mlimits)
		ri.BytesIn = src.n
		if err != nil {
			if v = multipart.AsViolation(err); v == nil {
				s.bodyError(w, ri, err)
				return body, true
			}
		}
		if s.control(w, ri, route, config.CtlMPart, func() *policy.Violation { return v }) {
			return body, true
		}
		if s.control(w, ri, route, config.CtlUProg, func() *policy.Violation {
			if res.UploadProgress {
				return multipart.UploadProgressViolation()
			}
			return nil
		}) {
			return body, true
		}
		r.Header.Set("Content-Type", multipart.ContentType(nb))
		swapBody(r, body)
		return body, false
	}

	body := s.pool.NewBody(max)
	_, err := body.ReadFrom(src)
	ri.BytesIn = src.n
	if err != nil {
		s.bodyError(w, ri, err)
		return body, true
	}
	if isMultipart && (mpartMode != config.ModeOff || uprogMode != config.ModeOff) {
		if s.inspectMultipart(w, ri, route, cfg, ct, body, mlimits) {
			return body, true
		}
	}
	if media == ctype.URLEncoded && (route.Mode(config.CtlURLEnc) != config.ModeOff || uprogMode != config.ModeOff) {
		if s.inspectURLEncoded(w, ri, route, cfg, body, remainingVars) {
			return body, true
		}
	}
	swapBody(r, body)
	return body, false
}

// inspectURLEncoded applies PA-URLENC and PA-UPROG to a spooled urlencoded
// body, which is always forwarded unchanged. It returns true if rejected.
func (s *Server) inspectURLEncoded(w http.ResponseWriter, ri *telemetry.RequestInfo, route *policy.Route, cfg *config.Config, body *spool.Body, remainingVars int) bool {
	lim := route.Limits
	res, v, err := urlenc.Check(body.Reader(), urlenc.Limits{
		Seps:                cfg.PHP.ArgSeparatorInput,
		MaxVars:             remainingVars,
		MaxNesting:          lim.MaxNesting,
		MaxKeyLength:        lim.MaxKeyLength,
		MaxValueLength:      int64(lim.MaxFieldValue),
		UploadProgressField: cfg.PHP.UploadProgressField,
	})
	if err != nil {
		s.bodyError(w, ri, err)
		return true
	}
	if s.control(w, ri, route, config.CtlURLEnc, func() *policy.Violation { return v }) {
		return true
	}
	uploadProgress := res.UploadProgress
	if v != nil && !uploadProgress && route.Mode(config.CtlUProg) != config.ModeOff {
		// The limited scan stopped early; check the rest of the body.
		found, err := urlenc.HasUploadProgress(body.Reader(), cfg.PHP.ArgSeparatorInput, cfg.PHP.UploadProgressField)
		uploadProgress = found || err != nil
	}
	return s.control(w, ri, route, config.CtlUProg, func() *policy.Violation {
		if uploadProgress {
			return multipart.UploadProgressViolation()
		}
		return nil
	})
}

// inspectMultipart evaluates a spooled multipart body that will be forwarded
// unchanged (PA-MPART not enforced). It returns true if PA-UPROG rejected it.
func (s *Server) inspectMultipart(w http.ResponseWriter, ri *telemetry.RequestInfo, route *policy.Route, cfg *config.Config, ct string, body *spool.Body, l multipart.Limits) bool {
	var v *policy.Violation
	uploadProgress, parsed := false, false
	if boundary, why := multipart.Boundary(ct); why != "" {
		v = &policy.Violation{Reason: why, Status: http.StatusBadRequest}
	} else {
		res, vv, err := multipart.Canonicalize(body.Reader(), boundary, "inspect", io.Discard, l)
		if err != nil {
			vv = multipart.AsViolation(err)
		}
		v, uploadProgress, parsed = vv, res.UploadProgress, vv == nil
	}
	s.control(w, ri, route, config.CtlMPart, func() *policy.Violation { return v })

	if !parsed && !uploadProgress && route.Mode(config.CtlUProg) != config.ModeOff {
		// The body could not be fully parsed, so fail closed: if the field
		// name appears anywhere, PHP may still see it.
		found, err := multipart.ContainsBytes(body.Reader(), []byte(cfg.PHP.UploadProgressField))
		uploadProgress = found || err != nil
	}
	return s.control(w, ri, route, config.CtlUProg, func() *policy.Violation {
		if uploadProgress {
			return multipart.UploadProgressViolation()
		}
		return nil
	})
}

// bodyVarBudget is max_vars minus the query string's variables: query and
// body variables share one cap (SPEC 5.4). The query is always counted,
// even when PA-QUERY is off, so disabling it cannot widen the body's share.
func bodyVarBudget(cfg *config.Config, lim config.Limits, rawQuery string) int {
	n := lim.MaxVars - query.Parse(rawQuery, cfg.PHP.ArgSeparatorInput).Pairs
	if n < 0 {
		return 0
	}
	return n
}

func multipartLimits(cfg *config.Config, lim config.Limits, fields int) multipart.Limits {
	return multipart.Limits{
		MaxParts:            lim.MaxParts,
		MaxFiles:            lim.MaxFiles,
		MaxFields:           fields,
		MaxNesting:          lim.MaxNesting,
		MaxFieldValue:       int64(lim.MaxFieldValue),
		AllowedHeaders:      lim.AllowedPartHeaders,
		UploadProgressField: cfg.PHP.UploadProgressField,
	}
}

// bodyError rejects a request whose body could not be read or stored.
func (s *Server) bodyError(w http.ResponseWriter, ri *telemetry.RequestInfo, err error) {
	switch {
	case errors.Is(err, spool.ErrTooLarge):
		s.reject(w, ri, http.StatusRequestEntityTooLarge, "body_too_large")
	case errors.Is(err, spool.ErrOverloaded):
		s.reject(w, ri, http.StatusServiceUnavailable, "overloaded")
	default:
		s.reject(w, ri, http.StatusBadRequest, "body_read_error")
	}
}

func swapBody(r *http.Request, body *spool.Body) {
	r.ContentLength = body.Size()
	if body.Size() == 0 {
		r.Body = http.NoBody
		return
	}
	r.Body = io.NopCloser(body.Reader())
}

// clientReader reads the request body from the client, enforcing the
// route's size cap and the minimum transfer rate: each read must complete
// by start + read_header_timeout + bytes_so_far / body_min_rate.
type clientReader struct {
	r     io.Reader
	rc    *http.ResponseController
	start time.Time
	grace time.Duration
	rate  float64
	max   int64
	n     int64
}

func newClientReader(w http.ResponseWriter, r io.Reader, cfg *config.Config, max int64) *clientReader {
	return &clientReader{
		r:     r,
		rc:    http.NewResponseController(w),
		start: time.Now(),
		grace: cfg.Server.ReadHeaderTimeout,
		rate:  float64(cfg.Server.BodyMinRateBytesPerSec),
		max:   max,
	}
}

func (c *clientReader) Read(p []byte) (int, error) {
	if c.n > c.max {
		return 0, spool.ErrTooLarge
	}
	if rem := c.max + 1 - c.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	allowed := c.grace + time.Duration(float64(c.n)/c.rate*float64(time.Second))
	_ = c.rc.SetReadDeadline(c.start.Add(allowed))
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, spool.ErrTooLarge
	}
	return n, err
}

// done clears the read deadline so it cannot affect the next request on the
// connection.
func (c *clientReader) done() { _ = c.rc.SetReadDeadline(time.Time{}) }
