// Package forwarded implements utilities for processing RFC 7239 headers.
package forwarded

import (
	"net/http"
	"strings"
)

var determiner Determiner = xffDeterminer{}

// By is the original user-facing interface which received this request, as
// described by the headers.
func By(h http.Header) string {
	return determiner.By(h)
}

// For is the interface which originally made this request, as described by the
// headers.
func For(h http.Header) string {
	return determiner.For(h)
}

// Host is the host for which the original request was made, as described by the
// headers.
func Host(h http.Header) string {
	return determiner.Host(h)
}

// Proto is the protocol over which the original request was made, as described
// by the headers.
func Proto(h http.Header) string {
	return determiner.Proto(h)
}

// Determiner of forwarding information about a request.
type Determiner interface {
	By(http.Header) string
	For(http.Header) string
	Host(http.Header) string
	Proto(http.Header) string
}

// xffDeterminer uses the legacy X-Forwarded-$X headers to determine forwarding
// information.
type xffDeterminer struct{}

const (
	headerXForwardedBy    = "X-Forwarded-By"
	headerXForwardedFor   = "X-Forwarded-For"
	headerXForwardedHost  = "X-Forwarded-Host"
	headerXForwardedProto = "X-Forwarded-Proto"
)

func (xffDeterminer) By(h http.Header) (by string) {
	if xfb := h.Get(headerXForwardedBy); xfb != "" {
		xfbs := strings.Split(xfb, ",")
		by = strings.TrimSpace(xfbs[0])
	}
	return
}

func (xffDeterminer) For(h http.Header) (f string) {
	if xff := h.Get(headerXForwardedFor); xff != "" {
		xffs := strings.Split(xff, ",")
		f = strings.TrimSpace(xffs[0])
	}
	return
}

func (xffDeterminer) Host(h http.Header) (host string) {
	if xfh := h.Get(headerXForwardedHost); xfh != "" {
		host = strings.TrimSpace(xfh)
	}
	return
}

func (xffDeterminer) Proto(h http.Header) (proto string) {
	if xfp := h.Get(headerXForwardedProto); xfp != "" {
		proto = strings.TrimSpace(xfp)
	}
	return
}

// rfc7239Determiner uses the RFC 7239 Forwarded header to determine forwarding
// information.
type rfc7239Determiner struct{}

const headerForwarded = "Forwarded"

type parsedHeader struct {
	fors  []string
	bys   []string
	host  string
	proto string
}

// parseForwarded parses the RFC 7239 Forwarded header, without considering
// extensions. An empty header results in an empty struct. A mangled segment or
// an extension segment will be silently ignored. A completely mangled header
// will result in unpredictable results.
func parseForwarded(h http.Header) (p parsedHeader) {
	if f := h.Get(headerForwarded); f != "" {
		for _, seg := range strings.FieldsFunc(strings.ToLower(f), func(r rune) bool {
			return r == ';' || r == ','
		}) {
			if parts := strings.Split(seg, "="); len(parts) == 2 {
				switch parts[0] {
				case "for":
					p.fors = append(p.fors, parts[1])
				case "by":
					p.bys = append(p.bys, parts[1])
				case "host":
					p.host = parts[1]
				case "proto":
					p.proto = parts[1]
				}
			}
		}
	}
	return
}

func (rfc7239Determiner) By(h http.Header) (by string) {
	if ph := parseForwarded(h); len(ph.bys) > 0 {
		by = ph.bys[0]
	}
	return
}

func (rfc7239Determiner) For(h http.Header) (f string) {
	if ph := parseForwarded(h); len(ph.fors) > 0 {
		f = ph.fors[0]
	}
	return
}

func (rfc7239Determiner) Host(h http.Header) string {
	return parseForwarded(h).host
}

func (rfc7239Determiner) Proto(h http.Header) string {
	return parseForwarded(h).proto
}
