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
	Quote    string `json:"quote"`              // base64-encoded raw quote bytes
	Type     string `json:"type,omitempty"`     // optional: "sgx", "tdx", "sev-snp", "nvidia-gpu", "tdx-gpu"
	GPUQuote string `json:"gpuQuote,omitempty"` // base64-encoded NVIDIA GPU evidence (for "tdx-gpu" combined attestation)
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
	// SEV-SNP fields
	Measurement string `json:"measurement,omitempty"` // SEV-SNP MEASUREMENT (48 bytes hex)
	HostData    string `json:"hostData,omitempty"`    // SEV-SNP HOST_DATA (32 bytes hex)
	ReportID    string `json:"reportId,omitempty"`    // SEV-SNP REPORT_ID (32 bytes hex)
	// GPU attestation (for combined tdx-gpu / sev-snp-gpu attestation)
	GPUAttestation *GPUAttestationResult `json:"gpuAttestation,omitempty"`
	Message        string                `json:"message,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// GPUAttestationResult holds the result of NVIDIA GPU attestation.
type GPUAttestationResult struct {
	Verified bool   `json:"verified"`
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
}

// quoteType auto-detects the attestation evidence type from raw bytes.
//
// Intel DCAP quotes start with a uint16 version (3=SGX, 4=TDX) followed
// by att_key_type (uint16, typically 2). AMD SEV-SNP reports use a uint32
// version (2-5) so bytes[2:4] are zero. We use this to disambiguate
// SEV-SNP v3 reports from SGX v3 quotes.
//
// NVIDIA GPU evidence cannot be auto-detected and must use the explicit
// "type" field in the request.
func quoteType(raw []byte) string {
	if len(raw) < 4 {
		return "unknown"
	}
	version16 := binary.LittleEndian.Uint16(raw[:2])
	switch version16 {
	case 2:
		// SEV-SNP report version 2 (uint32 version = 2, bytes[2:4] = 0)
		if len(raw) >= 0x4A0 {
			return "sev-snp"
		}
	case 3:
		// Disambiguate: SGX DCAP v3 (att_key_type at offset 2) vs SEV-SNP v3.
		// SGX: bytes[2:4] = att_key_type (usually 2 = ECDSA-P256-SHA256).
		// SEV-SNP: bytes[2:4] = upper 16 bits of uint32 version = 0.
		attKeyType := binary.LittleEndian.Uint16(raw[2:4])
		if attKeyType == 0 && len(raw) >= 0x4A0 {
			return "sev-snp"
		}
		return "sgx"
	case 4:
		// Could also be SEV-SNP v4 if att_key_type == 0, but v4 not yet
		// released. Prefer TDX for now.
		attKeyType := binary.LittleEndian.Uint16(raw[2:4])
		if attKeyType == 0 && len(raw) >= 0x4A0 {
			return "sev-snp"
		}
		return "tdx"
	case 5:
		// SEV-SNP report version 5
		if len(raw) >= 0x4A0 {
			return "sev-snp"
		}
	}
	return "unknown"
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

	// Determine evidence type: explicit "type" field takes precedence.
	qType := req.Type
	if qType == "" {
		qType = quoteType(quoteRaw)
	}
	logInfo("quote received", "type", qType, "bytes", len(quoteRaw))

	switch qType {
	case "tdx":
		verifyTDXTotal.Add(1)
		verifyTDX(w, quoteRaw, start)
	case "sgx":
		verifySGXTotal.Add(1)
		verifySGX(w, quoteRaw, start)
	case "sev-snp":
		verifySEVSNPTotal.Add(1)
		verifySEVSNP(w, quoteRaw, start)
	case "nvidia-gpu":
		verifyNVIDIAGPUTotal.Add(1)
		verifyNVIDIAGPU(w, quoteRaw, start)
	case "tdx-gpu":
		verifyTDXTotal.Add(1)
		verifyNVIDIAGPUTotal.Add(1)
		verifyTDXGPUTotal.Add(1)
		verifyTDXGPU(w, quoteRaw, req.GPUQuote, start)
	default:
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported quote format (type=%q)", qType),
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

// verifyTDXGPU performs combined Intel TDX + NVIDIA GPU attestation.
// The TDX quote verifies CPU/memory confidentiality; the GPU evidence
// (forwarded to NRAS) verifies the GPU is in CC mode.
func verifyTDXGPU(w http.ResponseWriter, tdxQuoteRaw []byte, gpuQuoteB64 string, start time.Time) {
	// 1. Verify TDX quote
	quote, err := tdxAbi.QuoteToProto(tdxQuoteRaw)
	if err != nil {
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			TeeType: "tdx-gpu",
			Error:   fmt.Sprintf("Failed to parse TDX quote: %v", err),
		})
		return
	}

	if err := tdxCheck.TdxQuote(quote, &tdxCheck.Options{}); err != nil {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			TeeType: "tdx-gpu",
			Error:   fmt.Sprintf("TDX quote verification failed: %v", err),
		})
		return
	}

	var mrtd string
	if len(tdxQuoteRaw) >= 232 {
		mrtd = hex.EncodeToString(tdxQuoteRaw[184:232])
	}

	// 2. Verify NVIDIA GPU evidence (if provided)
	var gpuResult *GPUAttestationResult
	if gpuQuoteB64 != "" {
		gpuEvidence, err := base64.StdEncoding.DecodeString(gpuQuoteB64)
		if err != nil {
			verifyFailTotal.Add(1)
			recordVerifyDuration(time.Since(start))
			sendJSON(w, 400, VerifyResponse{
				Success: false,
				TeeType: "tdx-gpu",
				Error:   "Invalid base64 in 'gpuQuote' field",
			})
			return
		}

		msg, gpuErr := forwardToNRAS(nvidiaVerifierURL, gpuEvidence)
		if gpuErr != nil {
			gpuResult = &GPUAttestationResult{
				Verified: false,
				Status:   "VERIFICATION_FAILED",
				Error:    gpuErr.Error(),
			}
		} else {
			gpuResult = &GPUAttestationResult{
				Verified: true,
				Status:   "OK",
				Message:  msg,
			}
		}
	}

	// Overall success requires TDX pass. GPU failure is reported but
	// does not block the TDX result (caller decides policy).
	overallSuccess := true
	status := "OK"
	msg := "TDX quote verified"
	if gpuResult != nil && gpuResult.Verified {
		msg = "TDX quote + NVIDIA GPU attestation verified"
	} else if gpuResult != nil && !gpuResult.Verified {
		overallSuccess = false
		status = "PARTIAL"
		msg = "TDX quote verified, NVIDIA GPU attestation failed"
	} else if gpuQuoteB64 == "" {
		msg = "TDX quote verified (no GPU evidence provided)"
	}

	if overallSuccess {
		verifySuccessTotal.Add(1)
	} else {
		verifyFailTotal.Add(1)
	}
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, VerifyResponse{
		Success:        overallSuccess,
		Status:         status,
		TeeType:        "tdx-gpu",
		MRTD:           mrtd,
		GPUAttestation: gpuResult,
		Message:        msg,
	})
}

// sendJSON writes a JSON response with the given status code.
func sendJSON(w http.ResponseWriter, status int, resp VerifyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
