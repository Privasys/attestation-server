// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	tdxAbi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
)

// Intel PCS API v4 SGX endpoints. Production talks to PCS directly (no local PCCS).
// NOTE: go-tdx-guest's pcs.TcbInfoURL/QeIdentityURL hardcode the TDX base, so the SGX
// path builds its own URLs here.
const (
	pcsSGXBaseV4 = "https://api.trustedservices.intel.com/sgx/certification/v4"

	// Issuer-chain response headers (PEM intermediate ‖ root, URL-escaped).
	hdrTcbInfoIssuerChain    = "Tcb-Info-Issuer-Chain"
	hdrQeIdentityIssuerChain = "Sgx-Enclave-Identity-Issuer-Chain"
	hdrPckCrlIssuerChain     = "Sgx-Pck-Crl-Issuer-Chain"
)

func sgxTcbInfoURL(fmspc string) string {
	return fmt.Sprintf("%s/tcb?fmspc=%s", pcsSGXBaseV4, fmspc)
}
func sgxQeIdentityURL() string { return pcsSGXBaseV4 + "/qe/identity" }
func sgxPckCrlURL(ca string) string {
	return fmt.Sprintf("%s/pckcrl?ca=%s&encoding=der", pcsSGXBaseV4, ca)
}

// httpsGetter fetches a URL and returns response headers + body. Mirrors the
// go-tdx-guest trust.HTTPSGetter shape so a caching layer can wrap it.
type httpsGetter interface {
	Get(url string) (map[string][]string, []byte, error)
}

// netGetter is the default httpsGetter over net/http with a bounded timeout.
type netGetter struct{ client *http.Client }

func newNetGetter(timeout time.Duration) *netGetter {
	return &netGetter{client: &http.Client{Timeout: timeout}}
}

func (g *netGetter) Get(u string) (map[string][]string, []byte, error) {
	resp, err := g.client.Get(u)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MiB cap
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Header, body, fmt.Errorf("PCS returned HTTP %d for %s", resp.StatusCode, u)
	}
	return resp.Header, body, nil
}

// cacheEntry is a stored PCS response with its fetch time.
type cacheEntry struct {
	header    map[string][]string
	body      []byte
	fetchedAt time.Time
}

// cachingGetter wraps a base getter, caching successful responses and serving them
// during a PCS outage up to graceWindow past the last successful fetch. This is the
// "cache + bounded grace" posture (option A): strict fail-closed == graceWindow 0.
// It fails closed only when there is no cache OR the grace has expired.
type cachingGetter struct {
	base        httpsGetter
	graceWindow time.Duration
	now         func() time.Time
	mu          sync.Mutex
	cache       map[string]cacheEntry
}

func newCachingGetter(base httpsGetter, grace time.Duration) *cachingGetter {
	return &cachingGetter{
		base:        base,
		graceWindow: grace,
		now:         time.Now,
		cache:       make(map[string]cacheEntry),
	}
}

func (c *cachingGetter) Get(u string) (map[string][]string, []byte, error) {
	header, body, err := c.base.Get(u)
	if err == nil {
		c.mu.Lock()
		c.cache[u] = cacheEntry{header: header, body: body, fetchedAt: c.now()}
		c.mu.Unlock()
		return header, body, nil
	}

	// PCS unreachable/error: serve cached collateral if within the grace window.
	c.mu.Lock()
	ent, ok := c.cache[u]
	c.mu.Unlock()
	if ok && c.now().Sub(ent.fetchedAt) <= c.graceWindow {
		return ent.header, ent.body, nil
	}
	return nil, nil, fmt.Errorf("PCS unavailable and no cached collateral within grace window: %w", err)
}

// headerToIssuerChain parses the intermediate + root certificates from a PCS
// issuer-chain header (URL-escaped PEM, intermediate first then root).
func headerToIssuerChain(header map[string][]string, phrase string) (intermediate, root *x509.Certificate, err error) {
	vals, ok := header[phrase]
	if !ok || len(vals) != 1 || vals[0] == "" {
		return nil, nil, fmt.Errorf("issuer-chain header %q missing or malformed", phrase)
	}
	chain, err := url.QueryUnescape(vals[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode issuer chain %q: %w", phrase, err)
	}
	interBlock, rem := pem.Decode([]byte(chain))
	if interBlock == nil || interBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("issuer chain %q: bad intermediate PEM", phrase)
	}
	rootBlock, _ := pem.Decode(rem)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("issuer chain %q: bad root PEM", phrase)
	}
	if intermediate, err = x509.ParseCertificate(interBlock.Bytes); err != nil {
		return nil, nil, fmt.Errorf("issuer chain %q: parse intermediate: %w", phrase, err)
	}
	if root, err = x509.ParseCertificate(rootBlock.Bytes); err != nil {
		return nil, nil, fmt.Errorf("issuer chain %q: parse root: %w", phrase, err)
	}
	return intermediate, root, nil
}

// verifyIssuerChain checks the header's root equals the PINNED Intel SGX Root CA and
// that the signing (intermediate) certificate chains to it. Returns the signing cert.
func verifyIssuerChain(intermediate, root *x509.Certificate) error {
	if !root.Equal(intelSGXRootCA) {
		return fmt.Errorf("collateral issuer-chain root is not the pinned Intel SGX Root CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(intelSGXRootCA)
	if _, err := intermediate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("collateral signing certificate does not chain to the pinned Intel root: %w", err)
	}
	return nil
}

// verifySignedBody verifies rawBody's ECDSA-P256/SHA-256 signature (Intel serves the
// signature as hex-encoded raw r‖s) using the signing certificate.
func verifySignedBody(signingCert *x509.Certificate, rawBody []byte, hexSig string) error {
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("decode collateral signature: %w", err)
	}
	der, err := tdxAbi.SignatureToDER(sig)
	if err != nil {
		return fmt.Errorf("convert collateral signature to DER: %w", err)
	}
	if err := signingCert.CheckSignature(x509.ECDSAWithSHA256, rawBody, der); err != nil {
		return fmt.Errorf("collateral body signature invalid: %w", err)
	}
	return nil
}

// rawField extracts the exact bytes of a top-level JSON field (the signed sub-object).
func rawField(body []byte, field string) ([]byte, string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, "", fmt.Errorf("parse collateral envelope: %w", err)
	}
	raw, ok := top[field]
	if !ok {
		return nil, "", fmt.Errorf("collateral envelope missing %q field", field)
	}
	var sig string
	if s, ok := top["signature"]; ok {
		_ = json.Unmarshal(s, &sig)
	}
	return raw, sig, nil
}

// fetchSGXTcbInfo retrieves and fully verifies SGX TCB info for an FMSPC:
// issuer chain pinned to the Intel root, then the ECDSA signature over the raw
// tcbInfo object. Returns the parsed pcs.TcbInfo ready for matchSGXTCBStatus.
func fetchSGXTcbInfo(fmspc string, getter httpsGetter) (pcs.TcbInfo, error) {
	var out pcs.TcbInfo
	header, body, err := getter.Get(sgxTcbInfoURL(fmspc))
	if err != nil {
		return out, fmt.Errorf("fetch SGX TCB info: %w", err)
	}
	inter, root, err := headerToIssuerChain(header, hdrTcbInfoIssuerChain)
	if err != nil {
		return out, err
	}
	if err := verifyIssuerChain(inter, root); err != nil {
		return out, err
	}
	raw, sig, err := rawField(body, "tcbInfo")
	if err != nil {
		return out, err
	}
	if err := verifySignedBody(inter, raw, sig); err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("unmarshal tcbInfo: %w", err)
	}
	return out, nil
}

// fetchSGXQeIdentity retrieves and fully verifies the SGX QE identity (enclaveIdentity).
func fetchSGXQeIdentity(getter httpsGetter) (pcs.EnclaveIdentity, error) {
	var out pcs.EnclaveIdentity
	header, body, err := getter.Get(sgxQeIdentityURL())
	if err != nil {
		return out, fmt.Errorf("fetch SGX QE identity: %w", err)
	}
	inter, root, err := headerToIssuerChain(header, hdrQeIdentityIssuerChain)
	if err != nil {
		return out, err
	}
	if err := verifyIssuerChain(inter, root); err != nil {
		return out, err
	}
	raw, sig, err := rawField(body, "enclaveIdentity")
	if err != nil {
		return out, err
	}
	if err := verifySignedBody(inter, raw, sig); err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("unmarshal enclaveIdentity: %w", err)
	}
	return out, nil
}

// fetchSGXPckCrl retrieves the PCK CRL for a CA ("processor"/"platform"), verifies it
// is signed by an issuer chaining to the pinned Intel root, and returns it.
func fetchSGXPckCrl(ca string, getter httpsGetter) (*x509.RevocationList, error) {
	header, body, err := getter.Get(sgxPckCrlURL(ca))
	if err != nil {
		return nil, fmt.Errorf("fetch PCK CRL: %w", err)
	}
	inter, root, err := headerToIssuerChain(header, hdrPckCrlIssuerChain)
	if err != nil {
		return nil, err
	}
	if err := verifyIssuerChain(inter, root); err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("parse PCK CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(inter); err != nil {
		return nil, fmt.Errorf("PCK CRL signature not from the pinned issuer chain: %w", err)
	}
	return crl, nil
}
