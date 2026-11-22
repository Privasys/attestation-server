package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testIdP is an OIDC issuer serving discovery and a JWKS with one P-256 key,
// counting the JWKS fetches.
type testIdP struct {
	srv       *httptest.Server
	key       *ecdsa.PrivateKey
	kid       string
	jwksFetch atomic.Int32
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{key: key, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		idp.jwksFetch.Add(1)
		b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "kid": idp.kid, "alg": "ES256", "use": "sig", "crv": "P-256",
			"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// token signs claims (iss is filled in) under kid.
func (idp *testIdP) token(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	claims["iss"] = idp.srv.URL
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, idp.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (idp *testIdP) verifier(t *testing.T) *OIDCVerifier {
	t.Helper()
	v, err := NewOIDCVerifier(&OIDCConfig{Issuers: []string{idp.srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuthenticateRequiresExpiry(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.verifier(t)

	if _, err := v.Authenticate(idp.token(t, idp.kid, map[string]any{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()})); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	_, err := v.Authenticate(idp.token(t, idp.kid, map[string]any{"sub": "a"}))
	if err == nil || !strings.Contains(err.Error(), "no expiry") {
		t.Fatalf("token without exp: err = %v, want a refusal", err)
	}
	_, err = v.Authenticate(idp.token(t, idp.kid, map[string]any{"sub": "a", "exp": time.Now().Add(-time.Minute).Unix()}))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token: err = %v, want a refusal", err)
	}
}
