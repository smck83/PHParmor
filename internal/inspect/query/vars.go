// Package query parses and checks PHP-style variable strings: the query
// string (PA-QUERY), and the same rules applied to cookie names (PA-HDR) and
// urlencoded bodies (PA-URLENC, M4).
//
// The parser models how PHP registers variables (main/php_variables.c:
// php_default_treat_data and php_register_variable_ex), so limits are
// counted the way PHP will see the input, not the way Go's net/url would.
package query

import "strings"

// Var is one variable as PHP would register it.
type Var struct {
	// Key is the decoded name as sent, before PHP's normalisation.
	Key string
	// Base is the top-level name PHP registers: decoded, truncated at NUL,
	// leading spaces removed, '.' and ' ' replaced with '_', and an
	// unmatched '[' (with the rest of the name) folded in with '_'.
	Base string
	// Depth is the number of [index] groups PHP parses.
	Depth int
}

// Result is the outcome of parsing one variable string.
type Result struct {
	// Pairs counts the non-empty separator-delimited segments, which is
	// what PHP's max_input_vars counts.
	Pairs int
	// Vars are the variables PHP registers, in order. Segments whose name
	// is empty after normalisation are not registered.
	Vars []Var
}

// Parse splits s on any byte in seps (PHP's arg_separator.input, "&" by
// default) and returns what PHP would register.
func Parse(s, seps string) Result { return parse(s, seps, false) }

// ParseCookies parses a Cookie header as PHP builds $_COOKIE: ';'
// separators, and leading whitespace stripped from each name.
func ParseCookies(s string) Result { return parse(s, ";", true) }

func parse(s, seps string, cookie bool) Result {
	var r Result
	for len(s) > 0 {
		seg := s
		if i := strings.IndexAny(s, seps); i >= 0 {
			seg, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		if seg == "" {
			continue // PHP tokenises with strtok, which skips empty tokens
		}
		r.Pairs++
		name := seg
		if i := strings.IndexByte(seg, '='); i >= 0 {
			name = seg[:i]
		}
		if cookie {
			name = strings.TrimLeft(name, " \t\n\v\f\r")
		}
		if v, ok := Register(Decode(name)); ok {
			r.Vars = append(r.Vars, v)
		}
	}
	return r
}

// Register applies PHP's variable-name rules to a decoded name. ok is false
// when PHP would not register the variable (empty name).
func Register(key string) (v Var, ok bool) {
	v.Key = key
	name := key
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i] // PHP handles names as C strings
	}
	name = strings.TrimLeft(name, " ")

	open := strings.IndexByte(name, '[')
	base := name
	if open >= 0 {
		base = name[:open]
	}
	base = strings.Map(underscoreSpaceDot, base)
	if base == "" {
		return v, false
	}
	if open < 0 {
		v.Base = base
		return v, true
	}

	rest := name[open:] // starts with '['
	for len(rest) > 0 && rest[0] == '[' {
		closeIdx := strings.IndexByte(rest[1:], ']')
		if closeIdx < 0 {
			if v.Depth == 0 {
				// Not an index: PHP turns the '[' into '_' and keeps the
				// rest of the name, replacing ' ', '.' and '['.
				base += "_" + strings.Map(underscoreSpaceDotBracket, rest[1:])
			}
			break
		}
		v.Depth++
		rest = rest[1+closeIdx+1:]
	}
	v.Base = base
	return v, true
}

func underscoreSpaceDot(r rune) rune {
	if r == ' ' || r == '.' {
		return '_'
	}
	return r
}

func underscoreSpaceDotBracket(r rune) rune {
	if r == ' ' || r == '.' || r == '[' {
		return '_'
	}
	return r
}

// Decode mirrors PHP's php_url_decode: '+' becomes a space, "%XX" with two
// hex digits is decoded, and any other '%' is kept literally.
func Decode(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b = append(b, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// ValidPercent reports whether every '%' in s starts a two-digit hex escape.
func ValidPercent(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
