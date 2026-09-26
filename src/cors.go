package main

import (
	"net/http"
	"strings"
)

// originAllowed returns true for any https origin, and for plain http on
// localhost for development.
//
// The list used to be hard-coded to Privasys front ends. It protected
// nothing: every endpoint that is not public is gated by an OIDC bearer
// token the caller must present in the Authorization header, and the
// server sets no cookies, so a browser holds no ambient credential here
// for a foreign page to ride. What the list did do was refuse the pages
// the platform serves under an adopter's own domain (an app's UI behind a
// custom hostname), whose attestation panel then could not verify a quote.
func originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	scheme, host, ok := strings.Cut(origin, "://")
	if !ok || host == "" {
		return false
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	switch strings.ToLower(scheme) {
	case "https":
		return true
	case "http":
		return host == "localhost" || host == "127.0.0.1"
	}
	return false
}

// withCORS wraps a handler so that:
//   - preflight (OPTIONS) requests from allowed origins receive a 204
//     with the appropriate Access-Control-Allow-* headers;
//   - actual requests from allowed origins get an Access-Control-Allow-Origin
//     header echoing the request's Origin (so credentialed XHRs work).
//
// Requests from disallowed origins are passed through unchanged - the
// browser will then enforce the same-origin policy on the client side.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if originAllowed(origin) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			// Preflight - respond immediately, even when the Origin
			// is not on the allow list, so the browser sees a clean
			// 204 instead of the 405 the mux would return for OPTIONS.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
