// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP revocation checking for the NVIDIA GPU attestation certificate chain.
//
// nvtrust checks the intermediates (indices [1, len-1): the short-lived GSP FMC
// leaf and the self-signed root are skipped) against NVIDIA's OCSP responder
// with a SHA-384 CertID. We replicate that: build one OCSP request per
// intermediate, POST it to the responder, verify the signed response binds to
// the cert, is fresh (within ThisUpdate/NextUpdate), and reports GOOD. Verified
// live against a real H100 chain: GSP BROM, GH100 Provisioner ICA 1 and GH100
// Identity all return good with a 24h validity window.
//
// Mode (nvidiaOCSPMode): "off" skips the check entirely; "soft" fails on a
// definitive REVOKED but tolerates responder/parse errors (recorded as a
// warning); "hard" fails on any OCSP error too. A REVOKED cert always fails
// regardless of mode.

// nvidiaOCSPURL is the NVIDIA OCSP responder (overridable via NV_OCSP_URL).
var nvidiaOCSPURL = envOrDefault("NV_OCSP_URL", "https://ocsp.ndis.nvidia.com/")

// nvidiaOCSPMode is "off" (default), "soft", or "hard"; set from --nvidia-ocsp.
var nvidiaOCSPMode = "off"

const ocspTimeout = 10 * time.Second

// ocspResult reports the outcome of the chain revocation check.
type ocspResult struct {
	checked bool
	revoked bool
	reason  string // populated when revoked
	warning string // responder/parse/unknown problems (soft-fail detail)
}

// ocspCheckGPUChain checks each intermediate certificate (indices [1, len-1))
// against the NVIDIA OCSP responder.
func ocspCheckGPUChain(chain []*x509.Certificate) ocspResult {
	if len(chain) < 3 {
		return ocspResult{checked: false, warning: "chain too short for OCSP"}
	}
	client := &http.Client{Timeout: ocspTimeout}
	var warnings []string
	for i := 1; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		resp, err := ocspStatusFor(client, cert, issuer)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", certCN(cert), err))
			continue
		}
		switch resp.Status {
		case ocsp.Revoked:
			return ocspResult{
				checked: true,
				revoked: true,
				reason:  fmt.Sprintf("%s revoked (reason %d) at %s", certCN(cert), resp.RevocationReason, resp.RevokedAt),
			}
		case ocsp.Unknown:
			warnings = append(warnings, fmt.Sprintf("%s: status unknown", certCN(cert)))
		}
	}
	res := ocspResult{checked: true}
	if len(warnings) > 0 {
		res.warning = strings.Join(warnings, "; ")
	}
	return res
}

// ocspStatusFor performs one OCSP round-trip for cert (issued by issuer) and
// returns the verified, fresh response.
func ocspStatusFor(client *http.Client, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	reqDER, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA384})
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq, err := http.NewRequest("POST", nvidiaOCSPURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("responder unreachable: %w", err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("responder HTTP %d", httpResp.StatusCode)
	}
	// ParseResponseForCert verifies the response signature (against the issuer or
	// a delegated responder cert embedded in the response) and binds it to cert.
	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("parse/verify response: %w", err)
	}
	// Freshness: reject a response outside its validity window (a small skew is
	// allowed for ThisUpdate).
	now := time.Now()
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return nil, fmt.Errorf("response expired at %s", resp.NextUpdate)
	}
	if now.Add(5 * time.Minute).Before(resp.ThisUpdate) {
		return nil, fmt.Errorf("response not yet valid (thisUpdate %s)", resp.ThisUpdate)
	}
	return resp, nil
}

func certCN(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
