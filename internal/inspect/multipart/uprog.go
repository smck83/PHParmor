package multipart

import (
	"bytes"
	"errors"
	"io"
)

// ContainsBytes reports whether needle occurs anywhere in r. PA-UPROG uses it
// as a fail-closed fallback when a body is forwarded without being
// canonicalised (PA-MPART in monitor or off) and could not be parsed: if the
// upload-progress field name appears anywhere, the field may reach PHP.
func ContainsBytes(r io.Reader, needle []byte) (bool, error) {
	if len(needle) == 0 {
		return false, nil
	}
	buf := make([]byte, 32<<10+len(needle))
	keep := 0
	for {
		n, err := r.Read(buf[keep:])
		window := buf[:keep+n]
		if bytes.Contains(window, needle) {
			return true, nil
		}
		// Keep the tail that could start a match spanning reads.
		keep = len(needle) - 1
		if keep > len(window) {
			keep = len(window)
		}
		copy(buf, window[len(window)-keep:])
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}
