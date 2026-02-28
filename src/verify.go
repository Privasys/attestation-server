package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	tdxAbi "github.com/google/go-tdx-guest/abi"
	tdxCheck "github.com/google/go-tdx-guest/verify"
)

// ---------------------------------------------------------------------------
//  DCAP verification
// ---------------------------------------------------------------------------

// VerifyRequest is the expected JSON body for POST /api/verify.
type VerifyRequest struct {
	Quote string `json:"quote"` // base64-encoded raw quote bytes
}

// VerifyResponse is returned by the verify and error endpoints.
type VerifyResponse struct {
	Success     bool     `json:"success"`
	Status      string   `json:"status,omitempty"`
	TcbDate     string   `json:"tcbDate,omitempty"`
	AdvisoryIDs []string `json:"advisoryIds,omitempty"`
	Message     string   `json:"message,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// quoteType detects whether raw bytes are an SGX (v3) or TDX (v4) quote
// by reading the little-endian uint16 version field at offset 0.
func quoteType(raw []byte) string {
	if len(raw) < 4 {
		return "unknown"
	}
	version := binary.LittleEndian.Uint16(raw[:2])
	switch version {
	case 3:
		return "sgx"
	case 4:
		return "tdx"
	default:
		return "unknown"
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse JSON body
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, 400, VerifyResponse{Success: false, Error: "Invalid JSON body"})
		return
	}
	if req.Quote == "" {
		sendJSON(w, 400, VerifyResponse{Success: false, Error: "Missing 'quote' field"})
		return
	}

	// 2. Base64-decode the quote
	quoteRaw, err := base64.StdEncoding.DecodeString(req.Quote)
	if err != nil {
		sendJSON(w, 400, VerifyResponse{Success: false, Error: "Invalid base64 in 'quote' field"})
		return
	}

	qType := quoteType(quoteRaw)
	log.Printf("Received %s quote (%d bytes)", qType, len(quoteRaw))

	switch qType {
	case "tdx":
		verifyTDX(w, quoteRaw)
	case "sgx":
		verifySGX(w, quoteRaw)
	default:
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported quote format (version %d)", binary.LittleEndian.Uint16(quoteRaw[:2])),
		})
	}
}

// verifyTDX uses google/go-tdx-guest to verify a TDX v4 quote in pure Go.
func verifyTDX(w http.ResponseWriter, quoteRaw []byte) {
	// Parse the raw quote into a structured object.
	quote, err := tdxAbi.QuoteToProto(quoteRaw)
	if err != nil {
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to parse TDX quote: %v", err),
		})
		return
	}

	// Verify the quote signature and certificate chain.
	// Options{} uses default verification (signature + cert chain only,
	// no collateral/TCB check — add TdxOptions for stricter checks).
	if err := tdxCheck.TdxQuote(quote, &tdxCheck.Options{}); err != nil {
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			Error:   fmt.Sprintf("TDX quote verification failed: %v", err),
		})
		return
	}

	sendJSON(w, 200, VerifyResponse{
		Success: true,
		Status:  "OK",
		Message: "TDX quote verified (signature + certificate chain)",
	})
}

// verifySGX uses the external 'check' binary to verify SGX v3 quotes.
func verifySGX(w http.ResponseWriter, quoteRaw []byte) {
	// Write raw quote to temporary file for the external tool.
	tmpFile, err := os.CreateTemp("", "quote-*.dat")
	if err != nil {
		sendJSON(w, 500, VerifyResponse{Success: false, Error: "Internal server error"})
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(quoteRaw); err != nil {
		tmpFile.Close()
		sendJSON(w, 500, VerifyResponse{Success: false, Error: "Failed to write quote"})
		return
	}
	tmpFile.Close()

	cmd := exec.Command("/home/bertrand/go-tdx/tools/check/check", "-in", tmpFile.Name())
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("SGX verification tool failed: %v, Output: %s", err, string(output))
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			Error:   fmt.Sprintf("SGX verification failed: %s", string(output)),
		})
		return
	}

	sendJSON(w, 200, VerifyResponse{
		Success: true,
		Status:  "OK",
		Message: "SGX quote verified via DCAP",
	})
}

// sendJSON writes a JSON response with the given status code.
func sendJSON(w http.ResponseWriter, status int, resp VerifyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
