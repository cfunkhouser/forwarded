package forwarded

import "net/http"

// ToRemoteAddr middleware sets the RemoteAddr on the http.Request to the
// forwarded host as determined by the provided strategy.
func ToRemoteAddr(next http.Handler, s Strategy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = s.For(r.Header)
		next.ServeHTTP(w, r)
	})
}
