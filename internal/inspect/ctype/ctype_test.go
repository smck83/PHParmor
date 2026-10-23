package ctype

import "testing"

func TestPHPMediaType(t *testing.T) {
	tests := map[string]string{
		"multipart/form-data; boundary=x":                  Multipart,
		"Multipart/Form-Data;boundary=x":                   Multipart,
		"multipart/form-data,x; boundary=y":                Multipart,
		"multipart/form-data boundary=y":                   Multipart,
		"multipart/form-data":                              Multipart,
		" multipart/form-data; boundary=x":                 "",
		"multipart/mixed; boundary=x":                      "multipart/mixed",
		"application/x-www-form-urlencoded":                URLEncoded,
		"APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8": URLEncoded,
		"application/json":                                 "application/json",
		"":                                                 "",
	}
	for in, want := range tests {
		if got := PHPMediaType(in); got != want {
			t.Errorf("PHPMediaType(%q) = %q, want %q", in, got, want)
		}
	}
}
