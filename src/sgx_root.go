// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// intelSGXRootCAPEM is the genuine Intel SGX Root CA — the single, stable trust
// anchor for every Intel SGX/TDX PCK certificate chain
// (https://certificates.trustedservices.intel.com/IntelSGXRootCA.der,
// subject "CN=Intel SGX Root CA, O=Intel Corporation", valid 2018-2049,
// SHA-256 fingerprint 44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3).
//
// A DCAP quote carries its own PCK cert chain, but the chain MUST anchor to
// THIS root — never to whatever self-signed cert the quote happens to include.
// Anchoring to the quote's own last cert (the previous behaviour) let a fully
// fabricated chain pass, i.e. a complete SGX attestation bypass. See
// .operations/enclave-vaults/attestation-hardening-plan.md.
const intelSGXRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

// intelSGXRootCAFingerprint is the SHA-256 of the pinned root's DER, asserted at
// init so a bad edit to the PEM above fails fast rather than silently.
const intelSGXRootCAFingerprint = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

// intelSGXRootCA is the parsed pinned root, set once at init.
var intelSGXRootCA *x509.Certificate

// sgxAllowDebug, when true, permits DEBUG-mode enclaves to pass verification.
// It defaults to FALSE (reject debug — a debug enclave's memory is readable by
// the host, so accepting one lets an attacker extract secrets from the "same"
// MRENCLAVE). Set SGX_ALLOW_DEBUG=1 only for a deployment that KNOWINGLY runs
// debug-signed enclaves; production must never enable it.
var sgxAllowDebug = os.Getenv("SGX_ALLOW_DEBUG") == "1"

func init() {
	block, _ := pem.Decode([]byte(intelSGXRootCAPEM))
	if block == nil {
		panic("attestation-server: embedded Intel SGX Root CA PEM failed to decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("attestation-server: embedded Intel SGX Root CA failed to parse: %v", err))
	}
	if got := hex.EncodeToString(sha256Sum(block.Bytes)); got != intelSGXRootCAFingerprint {
		panic(fmt.Sprintf("attestation-server: Intel SGX Root CA fingerprint mismatch: got %s, want %s", got, intelSGXRootCAFingerprint))
	}
	if !strings.Contains(cert.Subject.CommonName, "Intel SGX Root CA") {
		panic(fmt.Sprintf("attestation-server: pinned root has unexpected subject %q", cert.Subject.CommonName))
	}
	intelSGXRootCA = cert
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
