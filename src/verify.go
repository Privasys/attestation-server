package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdxAbi "github.com/google/go-tdx-guest/abi"
	tdxCheck "github.com/google/go-tdx-guest/verify"
)

// ---------------------------------------------------------------------------
//  Quote verification
// ---------------------------------------------------------------------------

// VerifyRequest is the expected JSON body for POST /api/verify.
type VerifyRequest struct {
	Quote string `json:"quote"` // base64-encoded raw quote bytes
}

// VerifyResponse is returned by the verify and error endpoints.
type VerifyResponse struct {
	Success     bool     `json:"success"`
	Status      string   `json:"status,omitempty"`
	TeeType     string   `json:"teeType,omitempty"`
	MREnclave   string   `json:"mrenclave,omitempty"`
	MRSigner    string   `json:"mrsigner,omitempty"`
	MRTD        string   `json:"mrtd,omitempty"`
	ISVProdID   *uint16  `json:"isvProdId,omitempty"`
	ISVSVN      *uint16  `json:"isvSvn,omitempty"`
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
	start := time.Now()
	verifyTotal.Add(1)

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
	logInfo("quote received", "type", qType, "bytes", len(quoteRaw))

	switch qType {
	case "tdx":
		verifyTDXTotal.Add(1)
		verifyTDX(w, quoteRaw, start)
	case "sgx":
		verifySGXTotal.Add(1)
		verifySGX(w, quoteRaw, start)
	default:
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported quote format (version %d)", binary.LittleEndian.Uint16(quoteRaw[:2])),
		})
	}
}

// verifyTDX uses google/go-tdx-guest to verify a TDX v4 quote in pure Go.
func verifyTDX(w http.ResponseWriter, quoteRaw []byte, start time.Time) {
	// Parse the raw quote into a structured object.
	quote, err := tdxAbi.QuoteToProto(quoteRaw)
	if err != nil {
		verifyFailTotal.Add(1)
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
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			Error:   fmt.Sprintf("TDX quote verification failed: %v", err),
		})
		return
	}

	// Extract MRTD from TDX report body (offset 184..232 in the raw quote)
	var mrtd string
	if len(quoteRaw) >= 232 {
		mrtd = hex.EncodeToString(quoteRaw[184:232])
	}

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, VerifyResponse{
		Success: true,
		Status:  "OK",
		TeeType: "tdx",
		MRTD:    mrtd,
		Message: "TDX quote verified (signature + certificate chain)",
	})
}

// verifySGX parses and cryptographically verifies an SGX DCAP Quote v3
// entirely in Go: ECDSA signatures, attestation key binding, and cert chain.
func verifySGX(w http.ResponseWriter, quoteRaw []byte, start time.Time) {
	quote, err := ParseSGXQuote(quoteRaw)
	if err != nil {
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to parse SGX quote: %v", err),
		})
		return
	}

	if err := quote.VerifyAll(); err != nil {
		logWarn("sgx verification failed", "error", err)
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			Error:   fmt.Sprintf("SGX quote verification failed: %v", err),
		})
		return
	}

	byteOrder := "big-endian"
	if quote.littleEndian {
		byteOrder = "little-endian"
	}
	prodID := quote.ISVProdID()
	svn := quote.ISVSVN()

	logInfo("sgx quote verified",
		"byte_order", byteOrder,
		"mrenclave", hex.EncodeToString(quote.MRENCLAVE()),
		"mrsigner", hex.EncodeToString(quote.MRSIGNER()),
	)

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, VerifyResponse{
		Success:   true,
		Status:    "OK",
		TeeType:   "sgx",
		MREnclave: hex.EncodeToString(quote.MRENCLAVE()),
		MRSigner:  hex.EncodeToString(quote.MRSIGNER()),
		ISVProdID: &prodID,
		ISVSVN:    &svn,
		Message:   "SGX DCAP Quote v3 verified (signature + attestation key binding + certificate chain)",
	})
}

// sendJSON writes a JSON response with the given status code.
func sendJSON(w http.ResponseWriter, status int, resp VerifyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
