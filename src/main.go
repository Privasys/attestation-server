package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
)

// ---------------------------------------------------------------------------
//  Configuration  (override via environment variables)
// ---------------------------------------------------------------------------

// JWT_SIGNING_KEY_FILE must point to a PEM-encoded Ed25519 private key.
// The corresponding public key is derived automatically.
//
//	Generate with:
//	  openssl genpkey -algorithm Ed25519 -out server-jwt.key
//	  openssl pkey -in server-jwt.key -pubout -out server-jwt.pub
var (
	signingKey   ed25519.PrivateKey
	verifyingKey ed25519.PublicKey
)

func loadSigningKey() {
	keyFile := os.Getenv("JWT_SIGNING_KEY_FILE")
	if keyFile == "" {
		log.Fatal("JWT_SIGNING_KEY_FILE environment variable is required")
	}
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Failed to read signing key %s: %v", keyFile, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatalf("No PEM block found in %s", keyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse Ed25519 private key: %v", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		log.Fatalf("Key in %s is not an Ed25519 private key", keyFile)
	}
	signingKey = priv
	verifyingKey = priv.Public().(ed25519.PublicKey)
	log.Printf("Loaded Ed25519 signing key from %s", keyFile)
}

func main() {
	loadSigningKey()

	// CLI: issue a key directly via command-line flags
	// Usage: JWT_SIGNING_KEY_FILE=server-jwt.key attestation-server issue --subject "acme" --days 90
	if len(os.Args) >= 2 && os.Args[1] == "issue" {
		cliIssue()
		return
	}

	// Protected: requires a valid JWT with "verify" scope
	http.HandleFunc("/api/verify", requireAuth(verifyHandler, "verify"))

	// Admin: requires a valid JWT with "admin" scope
	http.HandleFunc("/api/issue", requireAuth(issueHandler, "admin"))

	fmt.Println("--- Privasys Attestation Server ---")
	fmt.Println("Listening on :8080")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/verify  (Bearer token, scope: verify)")
	fmt.Println("  POST /api/issue   (Bearer token, scope: admin)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
