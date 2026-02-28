package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
//  JWT helpers
// ---------------------------------------------------------------------------

// APIKeyClaims are the claims embedded in every issued API key.
type APIKeyClaims struct {
	jwt.RegisteredClaims
	// Scope can restrict access (e.g. "verify", "verify,admin").
	Scope string `json:"scope,omitempty"`
}

// ValidateAPIKey parses and validates a Bearer token.
func ValidateAPIKey(tokenStr string) (*APIKeyClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &APIKeyClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return verifyingKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*APIKeyClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// requireAuth is middleware that validates the Bearer token.
func requireAuth(next http.HandlerFunc, requiredScope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			sendJSON(w, 401, VerifyResponse{Success: false, Error: "Missing Authorization header"})
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			sendJSON(w, 401, VerifyResponse{Success: false, Error: "Authorization must use Bearer scheme"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		claims, err := ValidateAPIKey(tokenStr)
		if err != nil {
			sendJSON(w, 401, VerifyResponse{Success: false, Error: fmt.Sprintf("Invalid API key: %v", err)})
			return
		}

		// Check scope
		if requiredScope != "" {
			scopes := strings.Split(claims.Scope, ",")
			found := false
			for _, s := range scopes {
				if strings.TrimSpace(s) == requiredScope {
					found = true
					break
				}
			}
			if !found {
				sendJSON(w, 403, VerifyResponse{Success: false, Error: "Insufficient scope"})
				return
			}
		}

		log.Printf("Authenticated request from %q (scope=%s, exp=%s)",
			claims.Subject, claims.Scope, claims.ExpiresAt.Time.Format(time.RFC3339))
		next(w, r)
	}
}
