// Package forwarded implements utilities for processing RFC 7239 headers.
package forwarded

import (
	"net/http"
	"strings"
)

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
