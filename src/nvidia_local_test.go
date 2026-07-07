// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"os"
	"testing"
)

// Live OCSP check of the real captured chain against the NVIDIA responder.
// Network-gated (set NV_OCSP_LIVE=1) so CI stays offline. The intermediates
// (GSP BROM, GH100 Provisioner ICA 1, GH100 Identity) should report not-revoked.
func TestOCSPGPUChain_LiveNotRevoked(t *testing.T) {
	if os.Getenv("NV_OCSP_LIVE") != "1" {
		t.Skip("set NV_OCSP_LIVE=1 to run the live NVIDIA OCSP check")
	}
	env, err := os.ReadFile("testdata/gpu-evidence-sample.bin")
	if err != nil {
		t.Skipf("sample envelope not present: %v", err)
	}
	ev, err := parseGPUEvidenceEnvelope(env)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	chain, err := parseGPUCertChain(ev.certChain)
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	res := ocspCheckGPUChain(chain)
	if res.revoked {
		t.Fatalf("chain reported revoked: %s", res.reason)
	}
	if res.warning != "" {
		t.Logf("OCSP warnings (non-fatal): %s", res.warning)
	}
	t.Logf("OCSP checked=%v revoked=%v", res.checked, res.revoked)
}

// A real GPU CC evidence envelope captured from m5-dev-ai (H100, driver
// 595.71.05) must verify: genuine NVIDIA GPU, CC PRODUCTION/ON, authentic
// nonce-bound SPDM report, chain rooted at the pinned NVIDIA Device Identity CA.
func TestVerifyGPUEvidenceLocal_RealEnvelope(t *testing.T) {
	env, err := os.ReadFile("testdata/gpu-evidence-sample.bin")
	if err != nil {
		t.Skipf("sample envelope not present: %v", err)
	}
	res := verifyGPUEvidenceLocal(env)
	if !res.Verified {
		t.Fatalf("real envelope must verify, got: %s", res.Error)
	}
	if res.GPUUUID == "" || res.Driver == "" {
		t.Fatalf("expected GPU identity populated: %+v", res)
	}
	if res.CCEnvironment != "PRODUCTION" {
		t.Fatalf("expected PRODUCTION, got %q", res.CCEnvironment)
	}
	// The pinned GH100 golden table (driver 595.71.05 / VBIOS 96.00.cf.00.01)
	// covers this captured envelope, so firmware measurements must match.
	if !res.MeasurementsVerified {
		t.Fatalf("expected MeasurementsVerified true for the pinned driver/VBIOS: %s", res.Message)
	}
}

// The runtime SPDM measurements re-derived from the signed report must match the
// pinned golden table for this GPU's exact driver + VBIOS.
func TestMatchGoldenMeasurements_RealReport(t *testing.T) {
	env, err := os.ReadFile("testdata/gpu-evidence-sample.bin")
	if err != nil {
		t.Skipf("sample envelope not present: %v", err)
	}
	ev, err := parseGPUEvidenceEnvelope(env)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	ok, msg := matchGoldenMeasurements(ev.report)
	if !ok {
		t.Fatalf("expected golden match, got: %s", msg)
	}
	t.Log(msg)
}

// Flipping any byte inside the measurement record must break the golden match
// (a tampered firmware measurement can never pass).
func TestMatchGoldenMeasurements_TamperFails(t *testing.T) {
	env, err := os.ReadFile("testdata/gpu-evidence-sample.bin")
	if err != nil {
		t.Skipf("sample envelope not present: %v", err)
	}
	ev, err := parseGPUEvidenceEnvelope(env)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	tam := append([]byte(nil), ev.report...)
	// Offset well inside the measurement record (past request(37) + response
	// header(8) + first block header(4)).
	tam[spdmRequestLen+8+4+10] ^= 0x01
	if ok, _ := matchGoldenMeasurements(tam); ok {
		t.Fatal("tampered measurement record must not match golden")
	}
}

// Tampering any byte of the signed report must fail the SPDM signature check —
// so a forged/altered report can never verify.
func TestVerifyGPUEvidenceLocal_TamperFails(t *testing.T) {
	env, err := os.ReadFile("testdata/gpu-evidence-sample.bin")
	if err != nil {
		t.Skipf("sample envelope not present: %v", err)
	}
	// Byte ~200 is well inside the report body (past the magic/version, nonce
	// TLV, report TLV header, and the echoed nonce).
	tam := append([]byte(nil), env...)
	tam[200] ^= 0x01
	if res := verifyGPUEvidenceLocal(tam); res.Verified {
		t.Fatal("tampered evidence must NOT verify")
	}
}

func TestVerifyGPUEvidenceLocal_RejectsGarbage(t *testing.T) {
	if res := verifyGPUEvidenceLocal([]byte("not an envelope")); res.Verified {
		t.Fatal("garbage must not verify")
	}
}
