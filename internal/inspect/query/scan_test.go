package query

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

var open = ScanLimits{Seps: "&", MaxVars: 1 << 30, MaxNesting: 1 << 30, MaxKeyLength: 1 << 20}

func scanAll(t *testing.T, s string, l ScanLimits) (ScanResult, []Var) {
	t.Helper()
	var vars []Var
	res, err := Scan(iotest.OneByteReader(strings.NewReader(s)), l, func(v Var) { vars = append(vars, v) })
	if err != nil {
		t.Fatal(err)
	}
	return res, vars
}

func TestScanLimits(t *testing.T) {
	l := ScanLimits{Seps: "&", MaxVars: 3, MaxNesting: 2, MaxKeyLength: 10, MaxValueLength: 5, StrictPercent: true}
	tests := []struct{ name, in, reason string }{
		{"ok", "a=1&b[x][y]=22222&c", ""},
		{"too many", "a&b&c&d", ReasonTooManyVars},
		{"empty segments skipped", "&&a&&b&&c&&", ""},
		{"too deep", "a[1][2][3]=x", ReasonTooDeep},
		{"key too long", "abcdefghijk=1", ReasonKeyTooLong},
		{"encoded key within limit", "%61%62%63%64%65%66%67%68%69%6a=1", ""},
		{"raw key over 3x limit", strings.Repeat("%61", 11) + "=1", ReasonKeyTooLong},
		{"value too large", "a=123456", ReasonValueTooLarge},
		{"encoded value within limit", "a=%31%32%33%34%35", ""},
		{"plus is one byte", "a=+++++", ""},
		{"bad percent in value", "a=%zz", ReasonBadPercent},
		{"bad percent in key", "%g1=x", ReasonBadPercent},
		{"truncated percent at end", "a=%4", ReasonBadPercent},
		{"truncated percent before separator", "a=%4&b=1", ReasonBadPercent},
		{"lone percent", "a=%", ReasonBadPercent},
		{"equals inside value", "a=b=c", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := scanAll(t, tt.in, l)
			if res.Reason != tt.reason {
				t.Fatalf("reason = %q, want %q", res.Reason, tt.reason)
			}
		})
	}
}

func TestScanLenientPercent(t *testing.T) {
	l := open
	l.MaxValueLength = 4
	for _, in := range []string{"a=%zz", "a=%", "a=%4", "a=%%41"} {
		if res, _ := scanAll(t, in, l); res.Reason != "" {
			t.Errorf("%q: %q", in, res.Reason)
		}
	}
}

func TestScanSeparators(t *testing.T) {
	l := open
	l.Seps = "&;"
	res, vars := scanAll(t, "a=1;b=2&c=3", l)
	if res.Pairs != 3 || len(vars) != 3 || vars[1].Base != "b" {
		t.Errorf("res=%+v vars=%+v", res, vars)
	}
	if r := Parse("a=1;b=2&c=3", "&;"); r.Pairs != 3 {
		t.Errorf("Parse pairs = %d", r.Pairs)
	}
}

// zeros is an endless reader of one repeated byte.
type zeros byte

func (z zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(z)
	}
	return len(p), nil
}

func TestScanHugeInputBoundedMemory(t *testing.T) {
	// 64 MiB of one key: rejected after 3*MaxKeyLength bytes are held.
	l := ScanLimits{Seps: "&", MaxVars: 10, MaxNesting: 8, MaxKeyLength: 256}
	res, err := Scan(io.LimitReader(zeros('k'), 64<<20), l, nil)
	if err != nil || res.Reason != ReasonKeyTooLong {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// A huge value with no value cap is streamed through.
	res, err = Scan(io.MultiReader(strings.NewReader("a="), io.LimitReader(zeros('v'), 64<<20)), l, nil)
	if err != nil || res.Reason != "" || res.Pairs != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestScanReadError(t *testing.T) {
	_, err := Scan(iotest.ErrReader(io.ErrUnexpectedEOF), open, nil)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v", err)
	}
}

// FuzzScanMatchesParse checks that the streaming scanner registers exactly
// the variables the string parser does, for any input and separators.
func FuzzScanMatchesParse(f *testing.F) {
	for _, s := range []string{"", "a=1&b=2", "a[b][c]=d&&e", "a[b", "%zz&+&=", "x\x00[y]=1;z", "%%41=1"} {
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, s string, semicolon bool) {
		seps := "&"
		if semicolon {
			seps = "&;"
		}
		want := Parse(s, seps)
		l := open
		l.Seps = seps
		var got []Var
		res, err := Scan(iotest.HalfReader(strings.NewReader(s)), l, func(v Var) { got = append(got, v) })
		if err != nil || res.Reason != "" {
			t.Fatalf("unexpected result %+v %v", res, err)
		}
		if res.Pairs != want.Pairs || len(got) != len(want.Vars) {
			t.Fatalf("pairs %d/%d vars %d/%d", res.Pairs, want.Pairs, len(got), len(want.Vars))
		}
		for i := range got {
			if got[i] != want.Vars[i] {
				t.Fatalf("var %d: scan %+v parse %+v", i, got[i], want.Vars[i])
			}
		}
	})
}
