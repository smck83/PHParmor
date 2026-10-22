package multipart

import "strings"

// Violation reasons from header parsing.
const (
	ReasonBadContentType   = "bad_content_type"
	ReasonBadBoundary      = "bad_boundary"
	ReasonBadDisposition   = "bad_disposition"
	ReasonDuplicateParam   = "duplicate_param"
	ReasonUnknownParam     = "unknown_param"
	ReasonFilenameExt      = "filename_ext"
	ReasonBadName          = "bad_name"
	ReasonBadFilename      = "bad_filename"
	ReasonBadPartType      = "bad_part_content_type"
	ReasonPartHeader       = "disallowed_part_header"
	ReasonTransferEncoding = "part_transfer_encoding"
)

type param struct {
	key   string // lowercased
	value string
}

// parseTyped parses `type *( OWS ";" OWS key "=" value )` strictly: the type
// must equal want (case-insensitive), keys are tokens and unique, values are
// tokens or quoted strings without backslash escapes. It returns "" or a
// violation reason.
func parseTyped(v, want string) ([]param, string) {
	if len(v) < len(want) || !strings.EqualFold(v[:len(want)], want) {
		return nil, "type"
	}
	rest := v[len(want):]
	var out []param
	seen := map[string]bool{}
	for {
		rest = trimOWS(rest)
		if rest == "" {
			return out, ""
		}
		if rest[0] != ';' {
			return nil, "syntax"
		}
		rest = trimOWS(rest[1:])
		k := 0
		for k < len(rest) && isTokenChar(rest[k]) {
			k++
		}
		if k == 0 || k == len(rest) || rest[k] != '=' {
			return nil, "syntax"
		}
		key := strings.ToLower(rest[:k])
		rest = rest[k+1:]

		var val string
		if rest != "" && rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				return nil, "syntax"
			}
			val = rest[1 : 1+end]
			if strings.ContainsRune(val, '\\') {
				return nil, "syntax"
			}
			rest = rest[end+2:]
		} else {
			j := 0
			for j < len(rest) && isTokenChar(rest[j]) {
				j++
			}
			if j == 0 {
				return nil, "syntax"
			}
			val, rest = rest[:j], rest[j:]
		}
		if seen[key] {
			return nil, ReasonDuplicateParam
		}
		seen[key] = true
		out = append(out, param{key: key, value: val})
	}
}

func trimOWS(s string) string { return strings.TrimLeft(s, " \t") }

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// isBoundaryChar reports whether c is in the RFC 2046 bchars set.
func isBoundaryChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("'()+_,-./:=? ", c) >= 0
}

// Boundary extracts the boundary from a multipart/form-data Content-Type,
// enforcing SPEC 6.1: exactly one boundary of 1 to 70 RFC 2046 characters,
// not ending in a space; no duplicate or unknown parameters (charset is
// tolerated); no quoted escapes.
func Boundary(contentType string) (string, string) {
	ps, why := parseTyped(contentType, "multipart/form-data")
	switch why {
	case "":
	case ReasonDuplicateParam:
		return "", ReasonDuplicateParam
	default:
		return "", ReasonBadContentType
	}
	boundary, found := "", false
	for _, p := range ps {
		switch p.key {
		case "boundary":
			boundary, found = p.value, true
		case "charset":
		default:
			return "", ReasonUnknownParam
		}
	}
	if !found || len(boundary) < 1 || len(boundary) > 70 || boundary[len(boundary)-1] == ' ' {
		return "", ReasonBadBoundary
	}
	for i := 0; i < len(boundary); i++ {
		if !isBoundaryChar(boundary[i]) {
			return "", ReasonBadBoundary
		}
	}
	return boundary, ""
}

// Disposition is a parsed part Content-Disposition.
type Disposition struct {
	Name        string
	Filename    string
	HasFilename bool
}

// Name and filename limits (SPEC 6.2).
const (
	MaxNameLen        = 256
	MaxFilenameLen    = 255
	MaxPartTypeLength = 128
)

// ParseDisposition parses a part Content-Disposition strictly (SPEC 6.2):
// type form-data, a required non-empty name, an optional filename, no
// filename*, no other or duplicate parameters, and no '"', '\', control
// characters or DEL in values.
func ParseDisposition(v string) (Disposition, string) {
	var d Disposition
	ps, why := parseTyped(v, "form-data")
	switch why {
	case "":
	case ReasonDuplicateParam:
		return d, ReasonDuplicateParam
	default:
		return d, ReasonBadDisposition
	}
	hasName, hasExt := false, false
	for _, p := range ps {
		switch p.key {
		case "name":
			d.Name, hasName = p.value, true
		case "filename":
			d.Filename, d.HasFilename = p.value, true
		case "filename*":
			hasExt = true
		case "name*":
			return d, ReasonFilenameExt
		default:
			return d, ReasonUnknownParam
		}
	}
	// PHP ignores filename* and uses filename. When both are present (as
	// .NET HttpClient always sends), the canonical part keeps filename and
	// drops filename*, which is exactly what PHP would use. filename* alone
	// is ambiguous: other parsers treat the part as a file, PHP as a field.
	if hasExt && !d.HasFilename {
		return d, ReasonFilenameExt
	}
	if !hasName || d.Name == "" || len(d.Name) > MaxNameLen || !printable(d.Name) {
		return d, ReasonBadName
	}
	if d.HasFilename && (len(d.Filename) > MaxFilenameLen || !printable(d.Filename)) {
		return d, ReasonBadFilename
	}
	return d, ""
}

// printable rejects '"', '\', C0 controls and DEL. Bytes >= 0x80 (UTF-8)
// are allowed.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
