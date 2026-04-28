package main

import (
	"net/http"
	"strings"
)

// allowedOriginSuffixes is the list of host suffixes (with leading
// dot) plus exact hosts that may issue cross-origin requests against
// the attestation server. We deliberately keep this hard-coded so the
// public deployment can be reasoned about without consulting env vars.
//
// Adding a new front-end domain? Add it here and ship a new build.
var allowedOriginSuffixes = []string{
	".privasys.org",
	".privasys.id",
}

var allowedOriginHosts = []string{
	"privasys.org",
	"privasys.id",
	// Local development - safe because the OIDC bearer-token check
	// still gates every non-public endpoint.
	"localhost",
	"127.0.0.1",
}

// originAllowed returns true when the supplied Origin header matches
// one of the configured suffixes / hosts. Comparison ignores the
// scheme and port (browsers always include both in Origin).
func originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	// Strip scheme.
	host := origin
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// Strip port.
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	for _, h := range allowedOriginHosts {
		if host == h {
			return true
		}
	}
	for _, s := range allowedOriginSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
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
