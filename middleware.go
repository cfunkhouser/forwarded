package forwarded

import "net/http"

// RemoteAddr middleware sets the RemoteAddr on the http.Request to the
// forwarded host as determined by the provided strategy.
func RemoteAddr(next http.Handler, strategy Determiner) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = strategy.For(r.Header)
		next.ServeHTTP(w, r)
	})
}
