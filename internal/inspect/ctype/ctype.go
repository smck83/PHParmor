// Package ctype classifies request Content-Type values the way PHP does.
package ctype

import "strings"

// Media types PHP parses into $_POST and $_FILES.
const (
	Multipart  = "multipart/form-data"
	URLEncoded = "application/x-www-form-urlencoded"
)

// PHPMediaType returns the media type PHP's SAPI derives from a Content-Type
// header (main/SAPI.c: sapi_read_post_data): the value is lowercased and cut
// at the first ';', ',' or ' '. Classifying bodies any other way would let
// a value such as "multipart/form-data,x; boundary=..." reach PHP's
// multipart parser without being inspected.
func PHPMediaType(contentType string) string {
	if i := strings.IndexAny(contentType, ";, "); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(contentType)
}
