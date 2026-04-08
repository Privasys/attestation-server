package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevverify "github.com/google/go-sev-guest/verify"
)

// verifySEVSNP parses and cryptographically verifies an AMD SEV-SNP
// attestation report using google/go-sev-guest.
//
// The data may be a raw 1184-byte report or an extended report (report
// followed by a GUID certificate table). When certificates are present
// they are used directly; otherwise the VCEK is fetched from the AMD
// Key Distribution Service (KDS).
func verifySEVSNP(w http.ResponseWriter, data []byte, start time.Time) {
	if len(data) < sevabi.ReportSize {
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("SEV-SNP data too short: %d bytes (need >= %d)", len(data), sevabi.ReportSize),
		})
		return
	}

	// Parse the report for field extraction.
	report, err := sevabi.ReportToProto(data[:sevabi.ReportSize])
	if err != nil {
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to parse SEV-SNP report: %v", err),
		})
		return
	}

	// Verify the report signature and certificate chain.
	if err := verifySEVSNPSignature(data); err != nil {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			TeeType: "sev-snp",
			Error:   fmt.Sprintf("SEV-SNP verification failed: %v", err),
		})
		return
	}

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, VerifyResponse{
		Success:     true,
		Status:      "OK",
		TeeType:     "sev-snp",
		Measurement: hex.EncodeToString(report.Measurement),
		HostData:    hex.EncodeToString(report.HostData),
		ReportID:    hex.EncodeToString(report.ReportId),
		Message:     "SEV-SNP report verified (signature + certificate chain)",
	})
}

// verifySEVSNPSignature verifies the SEV-SNP report cryptographically.
// It first tries parsing as an extended report (report + certificate
// table) so that SnpAttestation can verify without network access.
// Falls back to RawSnpReport which fetches the VCEK from AMD KDS.
func verifySEVSNPSignature(data []byte) error {
	opts := sevverify.DefaultOptions()

	// Extended report: report followed by a certificate table.
	if len(data) > sevabi.ReportSize {
		attestation, err := sevabi.ReportCertsToProto(data)
		if err == nil && attestation.GetCertificateChain() != nil {
			return sevverify.SnpAttestation(attestation, opts)
		}
		// Fall through if cert parsing fails.
	}

	// Report-only: download VCEK from AMD KDS and verify.
	return sevverify.RawSnpReport(data[:sevabi.ReportSize], opts)
}
