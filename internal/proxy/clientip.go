package proxy

import (
	"net"
	"net/netip"
	"strings"
)

// PeerAddr parses the IP from an http.Request RemoteAddr ("ip:port").
func PeerAddr(remoteAddr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// Trusted reports whether a is inside any of the trusted prefixes.
func Trusted(a netip.Addr, trusted []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP resolves the client address (SPEC section 8.2). If the TCP peer is
// not trusted, X-Forwarded-For is ignored and the peer is the client.
// Otherwise X-Forwarded-For is walked from the right, skipping trusted
// addresses; the first untrusted address is the client. If an entry cannot be
// parsed, the walk stops and the last trusted hop is used, because nothing to
// its left can be relied on. If every entry is trusted, the leftmost is used.
func ClientIP(peer netip.Addr, xff []string, trusted []netip.Prefix) netip.Addr {
	if !Trusted(peer, trusted) {
		return peer
	}
	var hops []string
	for _, h := range xff {
		hops = append(hops, strings.Split(h, ",")...)
	}
	last := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return last
		}
		a = a.Unmap()
		if !Trusted(a, trusted) {
			return a
		}
		last = a
	}
	return last
}
