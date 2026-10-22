package proxy

import (
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("192.168.1.1/32")}
	tests := []struct {
		name string
		peer string
		xff  []string
		want string
	}{
		{"untrusted peer ignores xff", "203.0.113.9", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted peer, no xff", "10.0.0.5", nil, "10.0.0.5"},
		{"trusted peer, one client", "10.0.0.5", []string{"198.51.100.7"}, "198.51.100.7"},
		{"rightmost untrusted wins over spoofed left", "10.0.0.5", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"skips trusted hops", "10.0.0.5", []string{"198.51.100.7, 10.0.1.1, 192.168.1.1"}, "198.51.100.7"},
		{"multiple headers concatenate", "10.0.0.5", []string{"198.51.100.7", "10.0.1.1"}, "198.51.100.7"},
		{"all trusted uses leftmost", "10.0.0.5", []string{"10.0.3.3, 10.0.2.2"}, "10.0.3.3"},
		{"garbage stops the walk", "10.0.0.5", []string{"198.51.100.7, junk, 10.0.2.2"}, "10.0.2.2"},
		{"garbage next to peer", "10.0.0.5", []string{"junk"}, "10.0.0.5"},
		{"ipv4-mapped ipv6 unmapped", "10.0.0.5", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"ipv6 client", "10.0.0.5", []string{"2001:db8::1"}, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientIP(netip.MustParseAddr(tt.peer), tt.xff, trusted)
			if got.String() != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestPeerAddr(t *testing.T) {
	tests := map[string]string{
		"10.0.0.1:1234":          "10.0.0.1",
		"[2001:db8::1]:443":      "2001:db8::1",
		"[::ffff:10.0.0.1]:8080": "10.0.0.1",
		"bogus":                  "invalid IP",
	}
	for in, want := range tests {
		if got := PeerAddr(in).String(); got != want {
			t.Errorf("PeerAddr(%q) = %s, want %s", in, got, want)
		}
	}
	if Trusted(netip.Addr{}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}) {
		t.Error("invalid address must never be trusted")
	}
}
