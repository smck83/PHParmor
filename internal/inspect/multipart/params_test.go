package multipart

import (
	"strings"
	"testing"
)

func TestBoundary(t *testing.T) {
	tests := []struct {
		ct, want, reason string
	}{
		{"multipart/form-data; boundary=abc", "abc", ""},
		{"Multipart/Form-Data;boundary=abc", "abc", ""},
		{`multipart/form-data; boundary="a b:c?"`, "a b:c?", ""},
		{"multipart/form-data; boundary=----WebKitFormBoundaryX3bY; charset=utf-8", "----WebKitFormBoundaryX3bY", ""},
		{"multipart/form-data; boundary=" + strings.Repeat("b", 70), strings.Repeat("b", 70), ""},
		{"multipart/form-data", "", ReasonBadBoundary},
		{"multipart/form-data; boundary=", "", ReasonBadContentType},
		{`multipart/form-data; boundary=""`, "", ReasonBadBoundary},
		{"multipart/form-data; boundary=" + strings.Repeat("b", 71), "", ReasonBadBoundary},
		{`multipart/form-data; boundary="ends with space "`, "", ReasonBadBoundary},
		{`multipart/form-data; boundary="bad;char"`, "", ReasonBadBoundary},
		{`multipart/form-data; boundary="esc\"aped"`, "", ReasonBadContentType},
		{"multipart/form-data; boundary=a; boundary=b", "", ReasonDuplicateParam},
		{"multipart/form-data; BOUNDARY=a; boundary=b", "", ReasonDuplicateParam},
		{"multipart/form-data; boundary=a; x=y", "", ReasonUnknownParam},
		{"multipart/form-data,x; boundary=a", "", ReasonBadContentType},
		{"multipart/form-data boundary=a", "", ReasonBadContentType},
		{"multipart/form-data; boundary = a", "", ReasonBadContentType},
		{"multipart/form-data; boundary=a;", "", ReasonBadContentType},
		{`multipart/form-data; boundary="unterminated`, "", ReasonBadContentType},
		{"multipart/mixed; boundary=a", "", ReasonBadContentType},
	}
	for _, tt := range tests {
		got, reason := Boundary(tt.ct)
		if got != tt.want || reason != tt.reason {
			t.Errorf("Boundary(%q) = %q, %q; want %q, %q", tt.ct, got, reason, tt.want, tt.reason)
		}
	}
}

func TestParseDisposition(t *testing.T) {
	tests := []struct {
		v      string
		want   Disposition
		reason string
	}{
		{`form-data; name="a"`, Disposition{Name: "a"}, ""},
		{`Form-Data; name=a`, Disposition{Name: "a"}, ""},
		{`form-data; name="f[]"; filename="x y.txt"`, Disposition{Name: "f[]", Filename: "x y.txt", HasFilename: true}, ""},
		{`form-data; name="up"; filename=""`, Disposition{Name: "up", HasFilename: true}, ""},
		{`form-data; name="ünï"; filename="résumé;v2.pdf"`, Disposition{Name: "ünï", Filename: "résumé;v2.pdf", HasFilename: true}, ""},
		{`attachment; name="a"`, Disposition{}, ReasonBadDisposition},
		{`form-data`, Disposition{}, ReasonBadName},
		{`form-data; name=""`, Disposition{}, ReasonBadName},
		{`form-data; filename="x"`, Disposition{}, ReasonBadName},
		{`form-data; name="` + strings.Repeat("n", 257) + `"`, Disposition{}, ReasonBadName},
		{`form-data; name="a"; filename="` + strings.Repeat("f", 256) + `"`, Disposition{}, ReasonBadFilename},
		{`form-data; name="a"; filename*=UTF-8''x.txt`, Disposition{}, ReasonFilenameExt},
		{`form-data; name=doc; filename=data.bin; filename*=utf-8''data.bin`, Disposition{Name: "doc", Filename: "data.bin", HasFilename: true}, ""},
		{`form-data; name="a"; filename*=utf-8''x; filename="plain.txt"`, Disposition{Name: "a", Filename: "plain.txt", HasFilename: true}, ""},
		{`form-data; name="a"; filename="x"; filename*=utf-8''x; filename*=utf-8''y`, Disposition{}, ReasonDuplicateParam},
		{`form-data; name*=UTF-8''a`, Disposition{}, ReasonFilenameExt},
		{`form-data; name="a"; name="b"`, Disposition{}, ReasonDuplicateParam},
		{`form-data; name="a"; Name="b"`, Disposition{}, ReasonDuplicateParam},
		{`form-data; name="a"; size=10`, Disposition{}, ReasonUnknownParam},
		{`form-data; name="a\"b"`, Disposition{}, ReasonBadDisposition},
		{`form-data; name="a\\b"`, Disposition{}, ReasonBadDisposition},
		{"form-data; name=\"a\x01b\"", Disposition{}, ReasonBadName},
		{"form-data; name=\"a\x7fb\"", Disposition{}, ReasonBadName},
		{"form-data; name=\"a\"; filename=\"x\ty\"", Disposition{}, ReasonBadFilename},
		{`form-data; name="a" junk`, Disposition{}, ReasonBadDisposition},
		{`form-data; name="a"; filename="b`, Disposition{}, ReasonBadDisposition},
	}
	for _, tt := range tests {
		got, reason := ParseDisposition(tt.v)
		if reason != tt.reason || (reason == "" && got != tt.want) {
			t.Errorf("ParseDisposition(%q) = %+v, %q; want %+v, %q", tt.v, got, reason, tt.want, tt.reason)
		}
	}
}

func FuzzBoundary(f *testing.F) {
	f.Add("multipart/form-data; boundary=abc")
	f.Add(`multipart/form-data; boundary="a b"; charset=utf-8`)
	f.Fuzz(func(t *testing.T, ct string) {
		b, reason := Boundary(ct)
		if reason != "" {
			return
		}
		if len(b) < 1 || len(b) > 70 || strings.HasSuffix(b, " ") {
			t.Fatalf("accepted bad boundary %q", b)
		}
		for i := 0; i < len(b); i++ {
			if !isBoundaryChar(b[i]) {
				t.Fatalf("accepted bad boundary char in %q", b)
			}
		}
	})
}

func FuzzParseDisposition(f *testing.F) {
	f.Add(`form-data; name="a"; filename="b"`)
	f.Fuzz(func(t *testing.T, v string) {
		d, reason := ParseDisposition(v)
		if reason != "" {
			return
		}
		if d.Name == "" || !printable(d.Name) || !printable(d.Filename) {
			t.Fatalf("accepted %+v from %q", d, v)
		}
	})
}
