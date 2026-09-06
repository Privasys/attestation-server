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
	tdxPb "github.com/google/go-tdx-guest/proto/tdx"
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
	// EventLog is an optional base64-encoded CC event log (CCEL). When
	// present on a TDX verification, the log is replayed and the
	// reconstructed registers must equal the quote's RTMRs; any
	// mismatch fails the verification. See eventlog.go.
	EventLog string `json:"eventLog,omitempty"`
	// IncludeEventLog asks for the parsed per-event digests in the
	// response (only meaningful together with EventLog).
	IncludeEventLog bool `json:"includeEventLog,omitempty"`
	// AllowedPlatformIds is an optional relying-party allow-list of hardware
	// platform identifiers (hex): the PCK certificate's Platform Instance ID,
	// or its PPID when the certificate carries no instance id, or the SEV-SNP
	// CHIP_ID. When non-empty the evidence must come from one of them, else
	// the verification fails with status PLATFORM_NOT_ALLOWED. See platform.go.
	AllowedPlatformIds []string `json:"allowedPlatformIds,omitempty"`
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
	// TCBStatus is the platform TCB status derived from Intel PCS collateral
	// (UpToDate, SWHardeningNeeded, ConfigurationAndSWHardeningNeeded, …), present
	// when SGX_TCB_MODE is report/enforce and collateral was obtained.
	TCBStatus string `json:"tcbStatus,omitempty"`
	// TDX runtime measurement registers (hex), present on successful
	// TDX verifications.
	RTMRs []string `json:"rtmrs,omitempty"`
	// EventLogVerified reports the CCEL cross-check outcome when an
	// event log was supplied: true means the log replays exactly to
	// the quote's RTMRs.
	EventLogVerified *bool          `json:"eventLogVerified,omitempty"`
	EventLog         []EventSummary `json:"eventLog,omitempty"`
	// SEV-SNP fields
	Measurement string `json:"measurement,omitempty"` // SEV-SNP MEASUREMENT (48 bytes hex)
	HostData    string `json:"hostData,omitempty"`    // SEV-SNP HOST_DATA (32 bytes hex)
	ReportID    string `json:"reportId,omitempty"`    // SEV-SNP REPORT_ID (32 bytes hex)
	// GPU attestation (for combined tdx-gpu / sev-snp-gpu attestation)
	GPUAttestation *GPUAttestationResult `json:"gpuAttestation,omitempty"`
	// Platform is the hardware identity read from the verified evidence (the
	// PCK certificate's SGX extension, or the SEV-SNP CHIP_ID), present on
	// every verification that reached the evidence, so a relying party can pin
	// the machines it operates (VerifyRequest.AllowedPlatformIds).
	Platform *PlatformIdentity `json:"platform,omitempty"`
	// PckRevocationChecked reports the outcome of the PCK revocation check
	// (revocation.go): true when the leaf and its issuing CA were checked against
	// Intel's current CRLs and are not revoked; false when the check failed or
	// found a revocation (rejected in enforce mode); absent when the check is off.
	PckRevocationChecked *bool  `json:"pckRevocationChecked,omitempty"`
	Message              string `json:"message,omitempty"`
	Error                string `json:"error,omitempty"`
}

// tdxPckChain is the PEM PCK certificate chain embedded in a parsed TDX quote.
func tdxPckChain(quote interface{}) []byte {
	q4, ok := quote.(*tdxPb.QuoteV4)
	if !ok {
		return nil
	}
	return q4.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
}

// parseTDXForTest returns the PEM PCK chain of a raw TDX quote (tests).
func parseTDXForTest(raw []byte) ([]byte, error) {
	quote, err := tdxAbi.QuoteToProto(raw)
	if err != nil {
		return nil, err
	}
	chain := tdxPckChain(quote)
	if len(chain) == 0 {
		return nil, fmt.Errorf("no PCK chain in quote")
	}
	return chain, nil
}

// applyPlatformPolicy records the evidence's platform identity in resp and
// enforces the request's allow-list. Returns false, with resp turned into a
// PLATFORM_NOT_ALLOWED failure, when the platform is not allowed or, with a
// non-empty list, when no identity could be read (fail closed). Without an
// allow-list an unreadable identity is only logged.
func applyPlatformPolicy(req *VerifyRequest, identity *PlatformIdentity, readErr error, resp *VerifyResponse) bool {
	resp.Platform = identity
	if readErr != nil {
		if len(req.AllowedPlatformIds) == 0 {
			logWarn("platform identity unavailable", "error", readErr)
			return true
		}
		resp.Success = false
		resp.Status = "PLATFORM_NOT_ALLOWED"
		resp.Error = fmt.Sprintf("platform allow-list: %v", readErr)
		return false
	}
	if err := platformAllowed(identity, req.AllowedPlatformIds); err != nil {
		logWarn("platform not allowed", "platform", identity.ID(), "error", err)
		resp.Success = false
		resp.Status = "PLATFORM_NOT_ALLOWED"
		resp.Error = err.Error()
		return false
	}
	return true
}

// tdxPlatformIdentity reads the PCK leaf embedded in a parsed TDX quote.
func tdxPlatformIdentity(quote interface{}) (*PlatformIdentity, error) {
	chain := tdxPckChain(quote)
	if len(chain) == 0 {
		return nil, fmt.Errorf("TDX quote carries no PCK certificate chain")
	}
	return platformIdentityFromChain(chain)
}

// GPUAttestationResult holds the result of NVIDIA GPU attestation.
type GPUAttestationResult struct {
	Verified bool   `json:"verified"`
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
	// Populated by the local NVIDIA verifier (verifyGPUEvidenceLocal).
	GPUUUID       string `json:"gpuUuid,omitempty"`
	Driver        string `json:"driver,omitempty"`
	VBIOS         string `json:"vbios,omitempty"`
	CCEnvironment string `json:"ccEnvironment,omitempty"`
	// MeasurementsVerified is true only once firmware/VBIOS measurements are
	// matched against a signed NVIDIA RIM (not yet implemented — see
	// nvidia_local.go). Verified can be true (genuine GPU, authentic report)
	// while this is false.
	MeasurementsVerified bool `json:"measurementsVerified"`
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
		verifyTDX(w, quoteRaw, &req, start)
	case "sgx":
		verifySGXTotal.Add(1)
		verifySGX(w, quoteRaw, &req, start)
	case "sev-snp":
		verifySEVSNPTotal.Add(1)
		verifySEVSNP(w, quoteRaw, &req, start)
	case "nvidia-gpu":
		verifyNVIDIAGPUTotal.Add(1)
		verifyNVIDIAGPU(w, quoteRaw, start)
	case "tdx-gpu":
		verifyTDXTotal.Add(1)
		verifyNVIDIAGPUTotal.Add(1)
		verifyTDXGPUTotal.Add(1)
		verifyTDXGPU(w, quoteRaw, &req, start)
	default:
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported quote format (type=%q)", qType),
		})
	}
}

// tdxMeasurements pulls MRTD and the four RTMRs out of a parsed quote.
func tdxMeasurements(quote interface{}) (mrtd string, rtmrs [][]byte, rtmrHex []string) {
	q4, ok := quote.(*tdxPb.QuoteV4)
	if !ok || q4.GetTdQuoteBody() == nil {
		return "", nil, nil
	}
	body := q4.GetTdQuoteBody()
	mrtd = hex.EncodeToString(body.GetMrTd())
	for _, r := range body.GetRtmrs() {
		rtmrs = append(rtmrs, r)
		rtmrHex = append(rtmrHex, hex.EncodeToString(r))
	}
	return mrtd, rtmrs, rtmrHex
}

// applyEventLogCrossCheck runs the CCEL replay against the quote's
// RTMRs when the request supplied an event log. It mutates resp with
// the outcome and returns false when verification must fail.
func applyEventLogCrossCheck(req *VerifyRequest, quoteRtmrs [][]byte, resp *VerifyResponse) bool {
	if req.EventLog == "" {
		return true
	}
	logRaw, err := base64.StdEncoding.DecodeString(req.EventLog)
	if err != nil {
		resp.Error = "Invalid base64 in 'eventLog' field"
		return false
	}
	events, err := crossCheckEventLog(logRaw, quoteRtmrs)
	verified := err == nil
	resp.EventLogVerified = &verified
	if err != nil {
		resp.Error = fmt.Sprintf("Event log cross-check failed: %v", err)
		return false
	}
	if req.IncludeEventLog {
		resp.EventLog = summarizeEvents(events)
	}
	return true
}

// verifyTDX uses google/go-tdx-guest to verify a TDX v4 quote in pure Go.
func verifyTDX(w http.ResponseWriter, quoteRaw []byte, req *VerifyRequest, start time.Time) {
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

	mrtd, rtmrs, rtmrHex := tdxMeasurements(quote)
	resp := VerifyResponse{
		Success: true,
		Status:  "OK",
		TeeType: "tdx",
		MRTD:    mrtd,
		RTMRs:   rtmrHex,
		Message: "TDX quote verified (signature + certificate chain)",
	}
	identity, ierr := tdxPlatformIdentity(quote)
	if !applyPlatformPolicy(req, identity, ierr, &resp) || !applyRevocationPolicy(tdxPckChain(quote), &resp) {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, resp)
		return
	}
	if !applyEventLogCrossCheck(req, rtmrs, &resp) {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		resp.Success = false
		resp.Status = "VERIFICATION_FAILED"
		sendJSON(w, 200, resp)
		return
	}
	if resp.EventLogVerified != nil && *resp.EventLogVerified {
		resp.Message = "TDX quote verified (signature + certificate chain); event log replays to attested RTMRs"
	}

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, resp)
}

// verifySGX parses and cryptographically verifies an SGX DCAP Quote v3
// entirely in Go: ECDSA signatures, attestation key binding, and cert chain.
func verifySGX(w http.ResponseWriter, quoteRaw []byte, req *VerifyRequest, start time.Time) {
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

	resp := VerifyResponse{
		Success:   true,
		Status:    "OK",
		TeeType:   "sgx",
		MREnclave: hex.EncodeToString(quote.MRENCLAVE()),
		MRSigner:  hex.EncodeToString(quote.MRSIGNER()),
		ISVProdID: &prodID,
		ISVSVN:    &svn,
		Message:   "SGX DCAP Quote v3 verified (signature + attestation key binding + certificate chain pinned to Intel SGX Root CA + non-debug)",
	}
	identity, ierr := platformIdentityFromChain(quote.QECertData)
	if !applyPlatformPolicy(req, identity, ierr, &resp) || !applyRevocationPolicy(quote.QECertData, &resp) {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, resp)
		return
	}

	// SGX_TCB_MODE report/enforce: derive the platform TCB status from Intel PCS
	// collateral. report never rejects (observability); enforce additionally applies
	// the secure floor. Off (default) skips the PCS round-trip entirely.
	if sgxTCBMode != "off" {
		certs, cerr := parsePEMChain(quote.QECertData)
		if cerr != nil {
			cerr = fmt.Errorf("parse PCK chain for TCB: %w", cerr)
		}
		var tcb sgxTCBResult
		if cerr == nil {
			tcb, cerr = deriveSGXTCB(certs, getCollateralGetter())
		}
		if cerr != nil {
			// Collateral unavailable/invalid.
			if sgxTCBMode == "enforce" {
				logWarn("sgx tcb check failed (enforce)", "error", cerr)
				verifyFailTotal.Add(1)
				recordVerifyDuration(time.Since(start))
				sendJSON(w, 200, VerifyResponse{
					Success: false,
					Status:  "VERIFICATION_FAILED",
					Error:   fmt.Sprintf("SGX TCB check failed: %v", cerr),
				})
				return
			}
			logWarn("sgx tcb check error (report-only, not rejecting)", "error", cerr)
		} else {
			resp.TCBStatus = string(tcb.Status)
			if resp.TcbDate == "" {
				resp.TcbDate = tcb.TcbDate
			}
			if len(resp.AdvisoryIDs) == 0 {
				resp.AdvisoryIDs = tcb.AdvisoryIDs
			}
			logInfo("sgx tcb status derived", "tcb_status", string(tcb.Status), "mode", sgxTCBMode)
			if sgxTCBMode == "enforce" {
				// Per-measurement policy relaxation is not plumbed yet, so enforce uses
				// the secure floor only. Revoked is always rejected.
				if aerr := tcbAcceptable(tcb.Status, nil); aerr != nil {
					logWarn("sgx tcb status rejected (enforce)", "tcb_status", string(tcb.Status), "error", aerr)
					verifyFailTotal.Add(1)
					recordVerifyDuration(time.Since(start))
					sendJSON(w, 200, VerifyResponse{
						Success:   false,
						Status:    "VERIFICATION_FAILED",
						TeeType:   "sgx",
						TCBStatus: string(tcb.Status),
						Error:     fmt.Sprintf("SGX TCB status not acceptable: %v", aerr),
					})
					return
				}
			}
		}
	}

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, resp)
}

// verifyTDXGPU performs combined Intel TDX + NVIDIA GPU attestation.
// The TDX quote verifies CPU/memory confidentiality; the GPU evidence
// (forwarded to NRAS) verifies the GPU is in CC mode.
func verifyTDXGPU(w http.ResponseWriter, tdxQuoteRaw []byte, req *VerifyRequest, start time.Time) {
	gpuQuoteB64 := req.GPUQuote
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

	mrtd, rtmrs, rtmrHex := tdxMeasurements(quote)

	// 1a. Platform identity, the request's allow-list, and PCK revocation.
	identity, ierr := tdxPlatformIdentity(quote)
	var platformResp VerifyResponse
	if !applyPlatformPolicy(req, identity, ierr, &platformResp) || !applyRevocationPolicy(tdxPckChain(quote), &platformResp) {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success:              false,
			Status:               platformResp.Status,
			TeeType:              "tdx-gpu",
			MRTD:                 mrtd,
			RTMRs:                rtmrHex,
			Platform:             identity,
			PckRevocationChecked: platformResp.PckRevocationChecked,
			Error:                platformResp.Error,
		})
		return
	}

	// 1b. Cross-check the CC event log against the quote's RTMRs.
	var elResp VerifyResponse
	if !applyEventLogCrossCheck(req, rtmrs, &elResp) {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success:          false,
			Status:           "VERIFICATION_FAILED",
			TeeType:          "tdx-gpu",
			MRTD:             mrtd,
			RTMRs:            rtmrHex,
			EventLogVerified: elResp.EventLogVerified,
			Error:            elResp.Error,
		})
		return
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

		gpuResult = verifyGPUEvidence(gpuEvidence)
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
		Success:          overallSuccess,
		Status:           status,
		TeeType:          "tdx-gpu",
		MRTD:             mrtd,
		RTMRs:            rtmrHex,
		EventLogVerified: elResp.EventLogVerified,
		EventLog:         elResp.EventLog,
		GPUAttestation:       gpuResult,
		Platform:             identity,
		PckRevocationChecked: platformResp.PckRevocationChecked,
		Message:              msg,
	})
}

// sendJSON writes a JSON response with the given status code.
func sendJSON(w http.ResponseWriter, status int, resp VerifyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
