// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"os"
	"testing"
)

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
	// RIM measurement matching is not implemented yet — must be honest.
	if res.MeasurementsVerified {
		t.Fatal("MeasurementsVerified must be false until RIM matching lands")
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
