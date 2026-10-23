// Sends the synthetic benign requests with Go's mime/multipart and net/http.
package main

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

func data(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func form(files bool) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if files {
		_ = w.WriteField("title", "report")
		f, _ := w.CreateFormFile("doc", "data.bin")
		_, _ = f.Write(data(4096))
		_, _ = w.CreateFormFile("empty", "empty.txt")
		f, _ = w.CreateFormFile("photos[]", "résumé ✓.png")
		_, _ = f.Write([]byte("fake png"))
	} else {
		for _, kv := range [][2]string{{"name", "Alice Example"}, {"tags[]", "one"}, {"tags[]", "two"},
			{"addr[home][city]", "Springfield"}, {"unicode", "héllo ✓"}, {"empty", ""}} {
			_ = w.WriteField(kv[0], kv[1])
		}
	}
	_ = w.Close()
	return &buf, w.FormDataContentType()
}

func post(name, ctype string, body io.Reader) {
	resp, err := http.Post(os.Getenv("BASE")+"/?corpus="+name, ctype, body)
	if err != nil {
		log.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("%s: %s", name, strings.TrimSpace(string(b)))
}

func main() {
	b, ct := form(false)
	post("go-fields", ct, b)
	b, ct = form(true)
	post("go-files", ct, b)
	// A reader without a known length makes net/http send it chunked.
	b, ct = form(true)
	post("go-chunked", ct, io.MultiReader(b))
}
