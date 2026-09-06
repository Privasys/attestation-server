// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

// PCK revocation.
//
// A quote's PCK certificate chain is verified to the pinned Intel SGX Root CA
// on every path, which says nothing about revocation: a platform whose PCK
// certificate Intel has revoked (a compromised key, for instance) still
// chains. This check consults Intel's CRLs: the PCK CRL of the
// issuing CA (Processor or Platform) for the leaf, and the Root CA CRL for the
// intermediate. It is independent of the TCB-status policy (SGX_TCB_MODE) and
// applies to SGX and TDX alike; both CRLs come through the caching PCS getter
// (24h grace through a PCS outage), so the steady state is a cache hit.
//
// PCK_REVOCATION_MODE: "enforce" (default) rejects a revoked certificate and,
// fail closed, a chain whose CRLs cannot be obtained; "report" only reports
// (pckRevocationChecked false in the response) and logs; "off" skips the check.
var pckRevocationMode = func() string {
	m := strings.ToLower(strings.TrimSpace(os.Getenv("PCK_REVOCATION_MODE")))
	switch m {
	case "off", "report":
		return m
	default:
		return "enforce"
	}
}()

// intelSGXRootCrlURL is Intel's Root CA CRL (DER), which lists revoked PCK CAs.
const intelSGXRootCrlURL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

// checkPckRevocation verifies that certs[0] (the PCK leaf) is not on the PCK CRL
// of its issuing CA and that certs[1] (the issuing CA) is not on the Root CA CRL.
// root is the pinned Intel SGX Root CA; now bounds the CRLs' validity.
func checkPckRevocation(certs []*x509.Certificate, getter httpsGetter, root *x509.Certificate, now time.Time) error {
	if len(certs) < 2 {
		return fmt.Errorf("PCK chain has %d certificate(s), need the leaf and its issuing CA", len(certs))
	}
	leaf, issuer := certs[0], certs[1]
	ca := "processor"
	if strings.Contains(issuer.Subject.CommonName, "Platform") {
		ca = "platform"
	}

	// 1. The PCK CRL of the issuing CA: served with its issuer chain, which must end at
	//    the pinned root, and signed by the CA that issued the leaf.
	header, body, err := getter.Get(sgxPckCrlURL(ca))
	if err != nil {
		return fmt.Errorf("fetch PCK CRL (%s): %w", ca, err)
	}
	signer, hdrRoot, err := headerToIssuerChain(header, hdrPckCrlIssuerChain)
	if err != nil {
		return err
	}
	if !hdrRoot.Equal(root) {
		return fmt.Errorf("PCK CRL issuer-chain root is not the pinned Intel SGX Root CA")
	}
	if err := chainsTo(signer, root); err != nil {
		return fmt.Errorf("PCK CRL signer: %w", err)
	}
	// The CRL must come from the CA that issued the leaf: same subject and the same key
	// (a distinguished name alone does not identify a CA).
	if !bytes.Equal(signer.RawSubject, leaf.RawIssuer) || !bytes.Equal(signer.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("PCK CRL is not issued by the leaf's issuing CA %q", leaf.Issuer.CommonName)
	}
	pckCrl, err := x509.ParseRevocationList(body)
	if err != nil {
		return fmt.Errorf("parse PCK CRL: %w", err)
	}
	if err := pckCrl.CheckSignatureFrom(signer); err != nil {
		return fmt.Errorf("PCK CRL signature: %w", err)
	}
	if err := crlCurrent(pckCrl, now, "PCK CRL"); err != nil {
		return err
	}
	for _, rc := range pckCrl.RevokedCertificateEntries {
		if rc.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return fmt.Errorf("PCK certificate %s is revoked (since %s)", leaf.SerialNumber.Text(16), rc.RevocationTime.UTC().Format(time.RFC3339))
		}
	}

	// 2. The Root CA CRL: the issuing CA itself must not be revoked.
	_, rootBody, err := getter.Get(intelSGXRootCrlURL)
	if err != nil {
		return fmt.Errorf("fetch Intel SGX Root CA CRL: %w", err)
	}
	rootCrl, err := x509.ParseRevocationList(rootBody)
	if err != nil {
		return fmt.Errorf("parse Intel SGX Root CA CRL: %w", err)
	}
	if err := rootCrl.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("Intel SGX Root CA CRL signature: %w", err)
	}
	if err := crlCurrent(rootCrl, now, "Intel SGX Root CA CRL"); err != nil {
		return err
	}
	for _, rc := range rootCrl.RevokedCertificateEntries {
		if rc.SerialNumber.Cmp(issuer.SerialNumber) == 0 {
			return fmt.Errorf("PCK issuing CA %q is revoked (since %s)", issuer.Subject.CommonName, rc.RevocationTime.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// chainsTo verifies that cert is issued (directly or through intermediates) by root.
func chainsTo(cert, root *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// crlCurrent rejects a CRL outside its validity window; a stale CRL served from the
// cache through a long PCS outage must not vouch for anything.
func crlCurrent(crl *x509.RevocationList, now time.Time, what string) error {
	if !crl.ThisUpdate.IsZero() && now.Before(crl.ThisUpdate.Add(-5*time.Minute)) {
		return fmt.Errorf("%s not yet valid (thisUpdate %s)", what, crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fmt.Errorf("%s expired (nextUpdate %s)", what, crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	return nil
}

// applyRevocationPolicy runs the revocation check on a PEM PCK chain per
// PCK_REVOCATION_MODE and records the outcome in resp. Returns false, with resp
// turned into a VERIFICATION_FAILED, when enforce mode rejects the chain.
func applyRevocationPolicy(pemChain []byte, resp *VerifyResponse) bool {
	if pckRevocationMode == "off" {
		return true
	}
	var err error
	certs, err := parsePEMChain(pemChain)
	if err == nil {
		err = checkPckRevocation(certs, getCollateralGetter(), intelSGXRootCA, time.Now())
	}
	checked := err == nil
	resp.PckRevocationChecked = &checked
	if err == nil {
		return true
	}
	if pckRevocationMode == "report" {
		logWarn("pck revocation check failed (report-only, not rejecting)", "error", err)
		return true
	}
	logWarn("pck revocation check failed (enforce)", "error", err)
	resp.Success = false
	resp.Status = "VERIFICATION_FAILED"
	resp.Error = fmt.Sprintf("PCK revocation check: %v", err)
	return false
}
