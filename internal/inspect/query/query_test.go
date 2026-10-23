package query

import (
	"strings"
	"testing"
)

func TestRegister(t *testing.T) {
	tests := []struct {
		key   string
		ok    bool
		base  string
		depth int
	}{
		{"a", true, "a", 0},
		{"a.b c", true, "a_b_c", 0},
		{"  lead", true, "lead", 0},
		{"a[]", true, "a", 1},
		{"a[b][c]", true, "a", 2},
		{"a[b]junk[c]", true, "a", 1}, // PHP ignores anything after a non-'[' following ']'
		{"a[b", true, "a_b", 0},       // unmatched '[' is not an index
		{"a[b.c d[e", true, "a_b_c_d_e", 0},
		{"a[b][c", true, "a", 1}, // unmatched at depth 1 keeps the parsed index
		{"a[[b]]", true, "a", 1},
		{"a.b[c.d]", true, "a_b", 1}, // only the base is normalised
		{"PHPSESSID\x00junk", true, "PHPSESSID", 0},
		{"", false, "", 0},
		{"[x]", false, "", 0},
		{"   ", false, "", 0},
		{"\x00a", false, "", 0},
	}
	for _, tt := range tests {
		v, ok := Register(tt.key)
		if ok != tt.ok || v.Base != tt.base || v.Depth != tt.depth {
			t.Errorf("Register(%q) = %+v, %v; want base=%q depth=%d ok=%v", tt.key, v, ok, tt.base, tt.depth, tt.ok)
		}
	}
}

func TestDecode(t *testing.T) {
	tests := map[string]string{
		"a+b":       "a b",
		"%41%62":    "Ab",
		"%zz":       "%zz",
		"%4":        "%4",
		"%":         "%",
		"100%":      "100%",
		"PHP%53ESS": "PHPSESS",
		"%00":       "\x00",
	}
	for in, want := range tests {
		if got := Decode(in); got != want {
			t.Errorf("Decode(%q) = %q, want %q", in, got, want)
		}
	}
	for s, want := range map[string]bool{"a%41": true, "": true, "%4": false, "%zz": false, "a%": false} {
		if ValidPercent(s) != want {
			t.Errorf("ValidPercent(%q) != %v", s, want)
		}
	}
}

func TestParse(t *testing.T) {
	r := Parse("a=1&&b[]=2&=3&c&d.e=4", '&')
	if r.Pairs != 5 {
		t.Errorf("Pairs = %d, want 5 (empty segments skipped)", r.Pairs)
	}
	var bases []string
	for _, v := range r.Vars {
		bases = append(bases, v.Base)
	}
	if got := strings.Join(bases, ","); got != "a,b,c,d_e" {
		t.Errorf("bases = %s", got)
	}

	c := Parse("PHPSESSID=x; \tother=y;;PHP%53ESSID=z", ';')
	if c.Pairs != 3 || len(c.Vars) != 3 || c.Vars[1].Base != "other" || c.Vars[2].Base != "PHPSESSID" {
		t.Errorf("cookie parse = %+v", c)
	}
	// Leading whitespace is only stripped for cookies.
	if q := Parse("+a=1", '&'); q.Vars[0].Base != "a" || q.Vars[0].Key != " a" {
		t.Errorf("query leading space = %+v", q.Vars)
	}
}

func TestCheck(t *testing.T) {
	l := Limits{MaxVars: 3, MaxNesting: 2, MaxKeyLength: 10, MaxLength: 64}
	tests := []struct {
		name, raw, reason string
	}{
		{"empty", "", ""},
		{"ok", "a=1&b[x][y]=2&c", ""},
		{"too long", strings.Repeat("a", 65), ReasonTooLong},
		{"too many vars", "a&b&c&d", ReasonTooManyVars},
		{"empty segments do not count", "a&&&&b&&&c", ""},
		{"unregistered names still count", "=1&=2&=3&=4", ReasonTooManyVars},
		{"too deep", "a[1][2][3]=x", ReasonTooDeep},
		{"encoded brackets count", "a%5B1%5D%5B2%5D%5B3%5D=x", ReasonTooDeep},
		{"junk after index is not depth", "a[1]x[2][]=x", ""},
		{"key too long", "abcdefghijk=1", ReasonKeyTooLong},
		{"key length is decoded", "%61%62%63%64%65=1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, v := Check(tt.raw, l)
			got := ""
			if v != nil {
				got = v.Reason
			}
			if got != tt.reason {
				t.Fatalf("reason = %q, want %q", got, tt.reason)
			}
		})
	}
	if _, v := Check(strings.Repeat("a", 65), l); v.Status != 414 {
		t.Errorf("too long status = %d", v.Status)
	}
	if _, v := Check("a&b&c&d", l); v.Status != 400 {
		t.Errorf("too many status = %d", v.Status)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"", "a=1&b=2", "a[b][c]=d", "a[b", "%zz&+&=", "a[[]]]", "x\x00[y]"} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, amp bool) {
		sep := byte('&')
		if !amp {
			sep = ';'
		}
		r := Parse(s, sep)
		if r.Pairs > strings.Count(s, string(sep))+1 {
			t.Fatalf("Pairs %d exceeds segments", r.Pairs)
		}
		if len(r.Vars) > r.Pairs {
			t.Fatalf("more vars than pairs")
		}
		brackets := strings.Count(Decode(s), "[")
		for _, v := range r.Vars {
			if v.Base == "" || v.Depth < 0 || v.Depth > brackets {
				t.Fatalf("bad var %+v", v)
			}
			if strings.ContainsAny(v.Base, " .") || strings.ContainsRune(v.Base, 0) {
				t.Fatalf("base not normalised: %q", v.Base)
			}
		}
	})
}
