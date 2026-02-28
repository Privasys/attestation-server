package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
//  API key issuance
// ---------------------------------------------------------------------------

// IssueAPIKey creates a signed JWT valid for the given duration.
//
// subject identifies the holder (e.g. "acme-corp", "alice@example.com").
// scope  is a comma-separated list of allowed actions (use "verify").
func IssueAPIKey(subject, scope string, validity time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := APIKeyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "privasys-attestation",
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(validity)),
			ID:        fmt.Sprintf("%d", now.UnixNano()),
		},
		Scope: scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(signingKey)
}

// ---------------------------------------------------------------------------
//  HTTP handler
// ---------------------------------------------------------------------------

// IssueRequest is the JSON body for POST /api/issue.
type IssueRequest struct {
	Subject   string `json:"subject"`
	Scope     string `json:"scope"`
	DaysValid int    `json:"days_valid"`
}

// IssueResponse is the JSON response from POST /api/issue.
type IssueResponse struct {
	Token   string `json:"token"`
	Subject string `json:"subject"`
	Scope   string `json:"scope"`
	Expires string `json:"expires"`
}

func issueHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var req IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, 400, VerifyResponse{Success: false, Error: "Invalid JSON body"})
		return
	}
	if req.Subject == "" {
		sendJSON(w, 400, VerifyResponse{Success: false, Error: "subject is required"})
		return
	}
	if req.DaysValid <= 0 {
		req.DaysValid = 30
	}
	if req.Scope == "" {
		req.Scope = "verify"
	}

	validity := time.Duration(req.DaysValid) * 24 * time.Hour
	token, err := IssueAPIKey(req.Subject, req.Scope, validity)
	if err != nil {
		sendJSON(w, 500, VerifyResponse{Success: false, Error: "Failed to issue token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(IssueResponse{
		Token:   token,
		Subject: req.Subject,
		Scope:   req.Scope,
		Expires: time.Now().UTC().Add(validity).Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
//  CLI key issuance
// ---------------------------------------------------------------------------

func cliIssue() {
	subject := "user"
	scope := "verify"
	days := 30

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--subject":
			i++
			if i < len(os.Args) {
				subject = os.Args[i]
			}
		case "--scope":
			i++
			if i < len(os.Args) {
				scope = os.Args[i]
			}
		case "--days":
			i++
			if i < len(os.Args) {
				fmt.Sscanf(os.Args[i], "%d", &days)
			}
		}
	}

	validity := time.Duration(days) * 24 * time.Hour
	token, err := IssueAPIKey(subject, scope, validity)
	if err != nil {
		log.Fatalf("Failed to issue token: %v", err)
	}

	expires := time.Now().UTC().Add(validity).Format(time.RFC3339)
	fmt.Printf("Subject : %s\n", subject)
	fmt.Printf("Scope   : %s\n", scope)
	fmt.Printf("Expires : %s\n", expires)
	fmt.Printf("Token   :\n%s\n", token)
}
