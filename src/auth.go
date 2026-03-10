package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
//  OIDC configuration
// ---------------------------------------------------------------------------

// OIDCConfig holds the OIDC verification settings.
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL (e.g. https://auth.example.com).
	Issuer string

	// Audience is the expected "aud" claim (e.g. "attestation-server").
	// Empty string disables audience validation.
	Audience string

	// ClientRole is the OIDC role required to call the verify endpoint.
	// Default: "attestation-server:client".
	ClientRole string

	// RoleClaim is the JWT claim key containing roles.
	// Default: "urn:zitadel:iam:org:project:roles".
	RoleClaim string
}

// ---------------------------------------------------------------------------
//  OIDC verifier
// ---------------------------------------------------------------------------

// OIDCVerifier validates OIDC bearer tokens via JWKS discovery.
type OIDCVerifier struct {
	cfg    *OIDCConfig
	jwks   *jwksCache
	jwksMu sync.RWMutex
}

// NewOIDCVerifier creates a verifier for the given OIDC configuration.
func NewOIDCVerifier(cfg *OIDCConfig) (*OIDCVerifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("OIDC issuer is required")
	}
	if cfg.ClientRole == "" {
		cfg.ClientRole = "attestation-server:client"
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "urn:zitadel:iam:org:project:roles"
	}
	return &OIDCVerifier{cfg: cfg}, nil
}

// Authenticate verifies an OIDC bearer token and checks the client role.
func (v *OIDCVerifier) Authenticate(tokenStr string) (subject string, err error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("header parse: %w", err)
	}

	// Get signing key from JWKS.
	jwk, err := v.getSigningKey(header.Kid, header.Alg)
	if err != nil {
		return "", fmt.Errorf("JWKS lookup: %w", err)
	}

	// Verify signature.
	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("sig decode: %w", err)
	}
	if err := jwkVerify(header.Alg, jwk, signingInput, sigBytes); err != nil {
		return "", fmt.Errorf("signature: %w", err)
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("claims decode: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", fmt.Errorf("claims parse: %w", err)
	}

	// Validate issuer.
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return "", fmt.Errorf("issuer %q != expected %q", iss, v.cfg.Issuer)
	}

	// Validate audience.
	if v.cfg.Audience != "" && !checkAudience(claims, v.cfg.Audience) {
		return "", fmt.Errorf("audience missing %q", v.cfg.Audience)
	}

	// Validate expiry.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", errors.New("token expired")
		}
	}

	// Check role.
	if !checkRole(claims, v.cfg.ClientRole, v.cfg.RoleClaim) {
		return "", fmt.Errorf("missing required role %q", v.cfg.ClientRole)
	}

	sub, _ := claims["sub"].(string)
	return sub, nil
}

// requireAuth is middleware that validates the OIDC Bearer token.
func requireAuth(next http.HandlerFunc, verifier *OIDCVerifier) http.HandlerFunc {
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

		subject, err := verifier.Authenticate(tokenStr)
		if err != nil {
			sendJSON(w, 401, VerifyResponse{Success: false, Error: fmt.Sprintf("Authentication failed: %v", err)})
			return
		}

		log.Printf("Authenticated request from %q", subject)
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
//  Audience / Role helpers
// ---------------------------------------------------------------------------

func checkAudience(claims map[string]interface{}, expected string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == expected
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// checkRole checks multiple claim paths for the required role:
//  1. The configured roleClaim (map of role→metadata, or array)
//  2. "roles" (standard string array)
//  3. "realm_access.roles" (Keycloak)
func checkRole(claims map[string]interface{}, role, roleClaim string) bool {
	// 1. Configured claim (may be a map: {"role-name": {...}} or an array).
	if raw, ok := claims[roleClaim]; ok {
		if roleMap, ok := raw.(map[string]interface{}); ok {
			if _, has := roleMap[role]; has {
				return true
			}
		}
		if arr, ok := raw.([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	// 2. Standard "roles" array.
	if raw, ok := claims["roles"]; ok {
		if arr, ok := raw.([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	// 3. Keycloak "realm_access.roles".
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if arr, ok := ra["roles"].([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
//  JWKS / OIDC discovery
// ---------------------------------------------------------------------------

type jwksCache struct {
	keys      map[string]*jwkKey
	fetchedAt time.Time
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type oidcDiscovery struct {
	JwksURI string `json:"jwks_uri"`
}

func (v *OIDCVerifier) getSigningKey(kid, alg string) (*jwkKey, error) {
	v.jwksMu.RLock()
	if v.jwks != nil && time.Since(v.jwks.fetchedAt) < 5*time.Minute {
		if key, ok := v.jwks.keys[kid]; ok {
			v.jwksMu.RUnlock()
			return key, nil
		}
	}
	v.jwksMu.RUnlock()

	v.jwksMu.Lock()
	defer v.jwksMu.Unlock()

	// Double-check after acquiring write lock.
	if v.jwks != nil && time.Since(v.jwks.fetchedAt) < 5*time.Minute {
		if key, ok := v.jwks.keys[kid]; ok {
			return key, nil
		}
	}

	jwksURI, err := v.discoverJWKS()
	if err != nil {
		return nil, err
	}
	keys, err := v.fetchJWKS(jwksURI)
	if err != nil {
		return nil, err
	}
	v.jwks = &jwksCache{keys: keys, fetchedAt: time.Now()}

	if key, ok := keys[kid]; ok {
		return key, nil
	}
	// If kid is empty, find matching alg.
	if kid == "" {
		for _, k := range keys {
			if k.Alg == alg || (k.Use == "sig" && k.Alg == "") {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("key %q not found in JWKS", kid)
}

func (v *OIDCVerifier) discoverJWKS() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := strings.TrimRight(v.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var disc oidcDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return "", fmt.Errorf("OIDC discovery parse: %w", err)
	}
	if disc.JwksURI == "" {
		return "", errors.New("OIDC discovery: no jwks_uri")
	}
	return disc.JwksURI, nil
}

func (v *OIDCVerifier) fetchJWKS(uri string) (map[string]*jwkKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var jwksResp jwksResponse
	if err := json.Unmarshal(body, &jwksResp); err != nil {
		return nil, fmt.Errorf("JWKS parse: %w", err)
	}
	keys := make(map[string]*jwkKey, len(jwksResp.Keys))
	for i := range jwksResp.Keys {
		k := &jwksResp.Keys[i]
		keys[k.Kid] = k
	}
	log.Printf("JWKS: fetched %d signing keys", len(keys))
	return keys, nil
}

// ---------------------------------------------------------------------------
//  JWK signature verification
// ---------------------------------------------------------------------------

func jwkVerify(alg string, key *jwkKey, signingInput, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return jwkVerifyRSA(alg, key, signingInput, sig)
	case strings.HasPrefix(alg, "ES"):
		return jwkVerifyEC(alg, key, signingInput, sig)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func jwkVerifyRSA(alg string, key *jwkKey, signingInput, sig []byte) error {
	if key.Kty != "RSA" {
		return fmt.Errorf("expected RSA key, got %s", key.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}

	var hashFunc crypto.Hash
	switch alg {
	case "RS256":
		hashFunc = crypto.SHA256
	case "RS384":
		hashFunc = crypto.SHA384
	case "RS512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	return rsa.VerifyPKCS1v15(pub, hashFunc, h.Sum(nil), sig)
}

func jwkVerifyEC(alg string, key *jwkKey, signingInput, sig []byte) error {
	if key.Kty != "EC" {
		return fmt.Errorf("expected EC key, got %s", key.Kty)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return err
	}

	var curve elliptic.Curve
	var keySize int
	var hashFn func([]byte) []byte

	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
		keySize = 32
		hashFn = func(data []byte) []byte { h := sha256.Sum256(data); return h[:] }
	case "P-384":
		curve = elliptic.P384()
		keySize = 48
		hashFn = func(data []byte) []byte { h := sha512.Sum384(data); return h[:] }
	default:
		return fmt.Errorf("unsupported curve: %s", key.Crv)
	}

	if len(sig) != keySize*2 {
		return fmt.Errorf("EC sig wrong length: %d, want %d", len(sig), keySize*2)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	hash := hashFn(signingInput)

	if !ecdsa.Verify(pub, hash, r, s) {
		return errors.New("EC signature verification failed")
	}
	return nil
}
