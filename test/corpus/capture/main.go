// Command capture records raw HTTP/1.1 requests, byte for byte, into the
// benign corpus. Point a real client at it with ?corpus=<name> in the URL;
// the request is written to <dir>/<name>.http. GET / serves a page whose
// buttons post FormData from the browser.
//
// Only synthetic content belongs in the corpus: never capture real user data.
package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

//go:embed page.html
var page []byte

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	dir := flag.String("dir", "test/corpus/benign", "output directory")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("capturing on %s into %s", ln.Addr(), *dir)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn, *dir)
	}
}

func handle(conn net.Conn, dir string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var raw bytes.Buffer
	br := bufio.NewReader(io.TeeReader(conn, &raw))
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("read request: %v", err)
		return
	}
	if req.Method == http.MethodGet && req.URL.Path == "/" {
		respond(conn, "200 OK", "text/html; charset=utf-8", page)
		return
	}
	if req.Header.Get("Expect") == "100-continue" {
		_, _ = io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n")
	}
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		log.Printf("read body: %v", err)
		return
	}
	// bufio may have read past the request; keep only what it consumed.
	captured := raw.Bytes()[:raw.Len()-br.Buffered()]

	name := req.URL.Query().Get("corpus")
	if !validName.MatchString(name) {
		respond(conn, "400 Bad Request", "text/plain", []byte("need ?corpus=<name> ([a-z0-9-])\n"))
		return
	}
	path := filepath.Join(dir, name+".http")
	if err := os.WriteFile(path, captured, 0o644); err != nil { // #nosec G306 -- test fixtures
		log.Printf("write %s: %v", path, err)
		respond(conn, "500 Internal Server Error", "text/plain", []byte("write failed\n"))
		return
	}
	log.Printf("captured %s (%d bytes)", path, len(captured))
	respond(conn, "200 OK", "text/plain", []byte("captured "+name+"\n"))
}

func respond(conn net.Conn, status, ctype string, body []byte) {
	h := "HTTP/1.1 " + status + "\r\nContent-Type: " + ctype +
		"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	_, _ = io.WriteString(conn, h)
	_, _ = conn.Write(body)
}
