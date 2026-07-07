// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Local NVIDIA GPU Confidential-Computing attestation verification — no
// external NRAS call in the data path. It proves the evidence is a genuine
// NVIDIA GPU in CC mode with an authentic, nonce-bound attestation report:
//
//  1. CC policy: PRODUCTION environment, CC feature ON, DevTools OFF.
//  2. Report authenticity: the SPDM attestation report is ECDSA-P384/SHA-384
//     signed (sig = last 96 bytes, big-endian r‖s) by the leaf (GSP FMC) key
//     over report[:-96]. Verified live on driver 595.71.05 / H100.
//  3. Chain of trust: the attestation cert chain links leaf→…→root and the
//     root is the pinned NVIDIA Device Identity CA (by DER equality).
//  4. Nonce self-consistency: the report echoes the envelope's declared nonce
//     at offset 4, so the signed report is bound to that nonce (the enclave
//     separately binds the nonce+evidence into the TDX quote REPORTDATA, which
//     the RA-TLS client checks — that is the CPU↔GPU / freshness bind).
//
// NOT YET verified locally (fail-OPEN on these is refused — they are reported
// as not-verified, never as verified): firmware/VBIOS measurement matching
// against a signed NVIDIA RIM, and OCSP revocation of the cert chain. Until
// those land, MeasurementsVerified stays false and a caller wanting golden-
// measurement assurance must treat the result accordingly.

// nvidiaDeviceIdentityCAPEM is the pinned NVIDIA Device Identity CA root
// (self-signed, P-384). Captured from a genuine GCP H100 and cross-checkable
// against NVIDIA's published root: SHA-256
// 102BF659D5419614C9D8E6AECEBC80454EB26B1DF6A769AC720B9A690B167B48.
const nvidiaDeviceIdentityCAPEM = `-----BEGIN CERTIFICATE-----
MIICCzCCAZCgAwIBAgIQLTZwscoQBBHB/sDoKgZbVDAKBggqhkjOPQQDAzA1MSIw
IAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE
SUEwIBcNMjExMTA1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDUxIjAgBgNVBAMM
GU5WSURJQSBEZXZpY2UgSWRlbnRpdHkgQ0ExDzANBgNVBAoMBk5WSURJQTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABA5MFKM7+KViZljbQSlgfky/RRnEQScW9NDZF8SX
gAW96r6u/Ve8ZggtcYpPi2BS4VFu6KfEIrhN6FcHG7WP05W+oM+hxj7nyA1r1jkB
2Ry70YfThX3Ba1zOryOP+MJ9vaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwHQYDVR0OBBYEFFeF/4PyY8xlfWi3Olv0jUrL+0lfMB8GA1UdIwQY
MBaAFFeF/4PyY8xlfWi3Olv0jUrL+0lfMAoGCCqGSM49BAMDA2kAMGYCMQCPeFM3
TASsKQVaT+8S0sO9u97PVGCpE9d/I42IT7k3UUOLSR/qvJynVOD1vQKVXf0CMQC+
EY55WYoDBvs2wPAH1Gw4LbcwUN8QCff8bFmV4ZxjCRr4WXTLFHBKjbfneGSBWwA=
-----END CERTIFICATE-----`

// P-384 signature length appended to the NVIDIA SPDM attestation report.
const gpuSigLen = 96

// gpuEvidence is the decoded envelope (mirrors
// enclave-os-virtual/internal/gpuattest.Evidence; the "PGAE" TLV wire format
// is duplicated here since the two live in different modules).
type gpuEvidence struct {
	nonce         [32]byte
	report        []byte
	certChain     []byte // PEM bundle
	uuid          string
	driver        string
	vbios         string
	ccEnvironment uint32
	ccFeature     uint32
	devToolsMode  uint32
}

// parseGPUEvidenceEnvelope decodes the "PGAE" v1 TLV envelope.
func parseGPUEvidenceEnvelope(b []byte) (*gpuEvidence, error) {
	if len(b) < 5 || string(b[:4]) != "PGAE" {
		return nil, errors.New("bad GPU evidence envelope magic")
	}
	if b[4] != 1 {
		return nil, fmt.Errorf("unsupported GPU evidence envelope version %d", b[4])
	}
	ev := &gpuEvidence{}
	p := 5
	for p < len(b) {
		if p+5 > len(b) {
			return nil, errors.New("truncated TLV header")
		}
		typ := b[p]
		l := binary.BigEndian.Uint32(b[p+1 : p+5])
		p += 5
		if int(l) > len(b)-p {
			return nil, errors.New("truncated TLV value")
		}
		v := b[p : p+int(l)]
		p += int(l)
		switch typ {
		case 0x01:
			if len(v) != 32 {
				return nil, errors.New("bad nonce length")
			}
			copy(ev.nonce[:], v)
		case 0x02:
			ev.report = v
		case 0x03:
			ev.certChain = v
		case 0x05:
			ev.uuid = string(v)
		case 0x06:
			ev.driver = string(v)
		case 0x07:
			ev.vbios = string(v)
		case 0x08:
			if len(v) == 4 {
				ev.ccEnvironment = binary.BigEndian.Uint32(v)
			}
		case 0x09:
			if len(v) == 4 {
				ev.ccFeature = binary.BigEndian.Uint32(v)
			}
		case 0x0a:
			if len(v) == 4 {
				ev.devToolsMode = binary.BigEndian.Uint32(v)
			}
		}
	}
	return ev, nil
}

// nvidiaVerifyMode selects "local" (default, no external call — the plan's
// chosen direction) or "nras" (forward to NVIDIA's Remote Attestation Service,
// requires --nvidia-nras-url). Set from --nvidia-verify-mode / NVIDIA_VERIFY_MODE.
var nvidiaVerifyMode = "local"

// verifyGPUEvidence dispatches GPU evidence verification per nvidiaVerifyMode.
func verifyGPUEvidence(evidence []byte) *GPUAttestationResult {
	if nvidiaVerifyMode == "nras" && nvidiaVerifierURL != "" {
		msg, err := forwardToNRAS(nvidiaVerifierURL, evidence)
		if err != nil {
			return &GPUAttestationResult{Verified: false, Status: "VERIFICATION_FAILED", Error: err.Error()}
		}
		return &GPUAttestationResult{Verified: true, Status: "OK", Message: msg}
	}
	return verifyGPUEvidenceLocal(evidence)
}

// verifyGPUEvidenceLocal performs the local NVIDIA GPU CC attestation
// verification described above and returns a populated GPUAttestationResult.
func verifyGPUEvidenceLocal(envelope []byte) *GPUAttestationResult {
	fail := func(format string, a ...any) *GPUAttestationResult {
		return &GPUAttestationResult{Verified: false, Status: "VERIFICATION_FAILED", Error: fmt.Sprintf(format, a...)}
	}

	ev, err := parseGPUEvidenceEnvelope(envelope)
	if err != nil {
		return fail("parse GPU evidence: %v", err)
	}

	// 1. CC policy — fail closed.
	if ev.ccFeature != 1 {
		return fail("GPU CC feature not ON (feature=%d)", ev.ccFeature)
	}
	if ev.ccEnvironment != 2 {
		return fail("GPU CC environment not PRODUCTION (env=%d)", ev.ccEnvironment)
	}
	if ev.devToolsMode != 0 {
		return fail("GPU CC DevTools mode is ON")
	}

	// 2. Nonce self-consistency: the signed report echoes the envelope nonce.
	if len(ev.report) < 36+gpuSigLen {
		return fail("GPU report too short (%d bytes)", len(ev.report))
	}
	if [32]byte(ev.report[4:36]) != ev.nonce {
		return fail("GPU report nonce does not match the envelope nonce")
	}

	// 3. Chain of trust to the pinned NVIDIA Device Identity CA.
	chain, err := parseGPUCertChain(ev.certChain)
	if err != nil || len(chain) < 2 {
		return fail("GPU attestation cert chain: %v", err)
	}
	if err := verifyChainToPinnedRoot(chain); err != nil {
		return fail("GPU cert chain: %v", err)
	}

	// 4. Report authenticity: SPDM signature by the leaf (GSP FMC) key.
	if err := verifyGPUReportSignature(ev.report, chain[0]); err != nil {
		return fail("GPU report signature: %v", err)
	}

	// 5. Firmware/VBIOS measurement matching against the pinned NVIDIA RIM golden
	// values (fail closed: MeasurementsVerified stays false on any gap). Only the
	// signed report's measurements are trusted here; the golden table was
	// XML-DSig-verified offline. OCSP revocation of the chain remains a TODO.
	measurementsVerified, measurementMsg := matchGoldenMeasurements(ev.report)

	msg := "genuine NVIDIA GPU in CC mode; authentic nonce-bound attestation report"
	if measurementsVerified {
		msg += "; " + measurementMsg
	} else {
		msg += "; firmware RIM match not established (" + measurementMsg + ")"
	}
	return &GPUAttestationResult{
		Verified:             true,
		Status:               "OK",
		GPUUUID:              ev.uuid,
		Driver:               ev.driver,
		VBIOS:                ev.vbios,
		CCEnvironment:        "PRODUCTION",
		MeasurementsVerified: measurementsVerified,
		Message:              msg,
	}
}

// parseGPUCertChain decodes a concatenated PEM bundle of certificates.
func parseGPUCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates in chain")
	}
	return certs, nil
}

// verifyChainToPinnedRoot checks each cert is signed by the next and that the
// final cert equals (DER) the pinned NVIDIA Device Identity CA. This is a
// manual chain walk (not x509.Verify) because the NVIDIA GPU PKI is not a
// TLS PKI and would trip x509's TLS-specific constraints. OCSP revocation is
// a documented TODO.
func verifyChainToPinnedRoot(chain []*x509.Certificate) error {
	pinned, err := pinnedNVIDIARoot()
	if err != nil {
		return err
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("link %d not signed by its issuer: %w", i, err)
		}
	}
	root := chain[len(chain)-1]
	// The presented root must be the pinned NVIDIA Device Identity CA, and be
	// self-signed (a genuine root, not an attacker-inserted intermediary).
	if !root.Equal(pinned) {
		return errors.New("chain root is not the pinned NVIDIA Device Identity CA")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("pinned root is not self-signed: %w", err)
	}
	return nil
}

var pinnedRootCache *x509.Certificate

func pinnedNVIDIARoot() (*x509.Certificate, error) {
	if pinnedRootCache != nil {
		return pinnedRootCache, nil
	}
	block, _ := pem.Decode([]byte(nvidiaDeviceIdentityCAPEM))
	if block == nil {
		return nil, errors.New("pinned NVIDIA root PEM invalid")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pinnedRootCache = c
	return c, nil
}

// verifyGPUReportSignature verifies the NVIDIA SPDM attestation report: the
// last 96 bytes are an ECDSA P-384 signature (big-endian r‖s) by the leaf key
// over report[:-96], hashed SHA-384. Validated live on a real H100 report.
func verifyGPUReportSignature(report []byte, leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().BitSize != 384 {
		return fmt.Errorf("leaf key is not ECDSA P-384 (%T)", leaf.PublicKey)
	}
	if len(report) < gpuSigLen+1 {
		return errors.New("report too short for signature")
	}
	sig := report[len(report)-gpuSigLen:]
	signed := report[:len(report)-gpuSigLen]
	r := new(big.Int).SetBytes(sig[:48])
	s := new(big.Int).SetBytes(sig[48:])
	h := sha512.Sum384(signed)
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("ECDSA-P384 signature invalid")
	}
	return nil
}

// gpuEvidenceSHA256 is SHA-256 of the whole envelope — the value the enclave
// folds into the TDX quote REPORTDATA (available for a future server-side
// bind check should the API start carrying the pubkey + binding).
func gpuEvidenceSHA256(envelope []byte) [32]byte { return sha256.Sum256(envelope) }
