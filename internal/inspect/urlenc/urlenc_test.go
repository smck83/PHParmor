package urlenc

import (
	"strings"
	"testing"

	"github.com/smck83/phparmor/internal/inspect/query"
)

var limits = Limits{
	Seps: "&", MaxVars: 3, MaxNesting: 2, MaxKeyLength: 12, MaxValueLength: 8,
	UploadProgressField: "PHP_SESSION_UPLOAD_PROGRESS",
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name, body, reason string
		status             int
	}{
		{"ok", "a=1&b[x]=2&c=", "", 0},
		{"too many vars", "a&b&c&d", query.ReasonTooManyVars, 413},
		{"too deep", "a[1][2][3]=x", query.ReasonTooDeep, 400},
		{"encoded nesting", "a%5B1%5D%5B2%5D%5B3%5D=x", query.ReasonTooDeep, 400},
		{"key too long", "abcdefghijklm=1", query.ReasonKeyTooLong, 400},
		{"value too large", "a=123456789", query.ReasonValueTooLarge, 413},
		{"invalid percent", "a=%zz", query.ReasonBadPercent, 400},
		{"truncated percent", "a=1&b=%2", query.ReasonBadPercent, 400},
		{"invalid percent in key", "a%=1", query.ReasonBadPercent, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, v, err := Check(strings.NewReader(tt.body), limits)
			if err != nil {
				t.Fatal(err)
			}
			if tt.reason == "" {
				if v != nil {
					t.Fatalf("unexpected %+v", v)
				}
				return
			}
			if v == nil || v.Reason != tt.reason || v.Status != tt.status {
				t.Fatalf("got %+v, want %s/%d", v, tt.reason, tt.status)
			}
		})
	}
}

func TestUploadProgress(t *testing.T) {
	for _, body := range []string{
		"PHP_SESSION_UPLOAD_PROGRESS=x",
		"a=1&PHP%5FSESSION%5FUPLOAD%5FPROGRESS=x",
		"PHP.SESSION.UPLOAD.PROGRESS=x",
		"PHP_SESSION_UPLOAD_PROGRESS[a]=x",
	} {
		l := limits
		l.MaxKeyLength = 64
		res, v, err := Check(strings.NewReader(body), l)
		if err != nil || v != nil || !res.UploadProgress {
			t.Errorf("%q: res=%+v v=%+v err=%v", body, res, v, err)
		}
		found, err := HasUploadProgress(strings.NewReader("junk=%zz&"+body), "&", "PHP_SESSION_UPLOAD_PROGRESS")
		if err != nil || !found {
			t.Errorf("%q: HasUploadProgress = %v %v", body, found, err)
		}
	}
	if res, _, _ := Check(strings.NewReader("PHP_SESSION=1"), limits); res.UploadProgress {
		t.Error("prefix matched")
	}
}

func TestCombinedCountIsCallerProvided(t *testing.T) {
	l := limits
	l.MaxVars = 0 // the query already used the whole budget
	_, v, _ := Check(strings.NewReader("a=1"), l)
	if v == nil || v.Reason != query.ReasonTooManyVars {
		t.Fatalf("got %+v", v)
	}
	if res, v, _ := Check(strings.NewReader(""), l); v != nil || res.Pairs != 0 {
		t.Fatalf("empty body: %+v %+v", res, v)
	}
}
