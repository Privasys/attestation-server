// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// A fake Intel PKI: root, a PCK Platform CA, a PCK leaf, and CRLs the test controls.
type fakePki struct {
	root, ca, leaf          *x509.Certificate
	rootKey, caKey          *ecdsa.PrivateKey
	pckRevoked, caRevoked   bool
	pckNextUpdate, rootNext time.Time
	now                     time.Time
}

func newFakePki(t *testing.T) *fakePki {
	t.Helper()
	now := time.Now()
	mk := func(cn string, serial int64, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			IsCA: isCA, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		if parent == nil {
			parent, parentKey = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, key
	}
	root, rootKey := mk("Fake SGX Root CA", 1, true, nil, nil)
	ca, caKey := mk("Intel SGX PCK Platform CA", 2, true, root, rootKey)
	leaf, _ := mk("Intel SGX PCK Certificate", 3, false, ca, caKey)
	return &fakePki{root: root, ca: ca, leaf: leaf, rootKey: rootKey, caKey: caKey,
		pckNextUpdate: now.Add(24 * time.Hour), rootNext: now.Add(24 * time.Hour), now: now}
}

func (p *fakePki) crl(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, revoked []*big.Int, next time.Time) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: p.now.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: p.now.Add(-time.Minute), NextUpdate: next, RevokedCertificateEntries: entries,
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// getter serves the two CRL URLs the way Intel PCS does (PCK CRL with the issuer chain header).
func (p *fakePki) getter(t *testing.T) httpsGetter {
	var pckRevoked, caRevoked []*big.Int
	if p.pckRevoked {
		pckRevoked = append(pckRevoked, p.leaf.SerialNumber)
	}
	if p.caRevoked {
		caRevoked = append(caRevoked, p.ca.SerialNumber)
	}
	pemOf := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return &mapGetter{responses: map[string]mapResponse{
		sgxPckCrlURL("platform"): {
			header: map[string][]string{hdrPckCrlIssuerChain: {url.QueryEscape(pemOf(p.ca) + pemOf(p.root))}},
			body:   p.crl(t, p.ca, p.caKey, pckRevoked, p.pckNextUpdate),
		},
		intelSGXRootCrlURL: {body: p.crl(t, p.root, p.rootKey, caRevoked, p.rootNext)},
	}}
}

type mapResponse struct {
	header map[string][]string
	body   []byte
}

type mapGetter struct{ responses map[string]mapResponse }

func (m *mapGetter) Get(u string) (map[string][]string, []byte, error) {
	r, ok := m.responses[u]
	if !ok {
		return nil, nil, os.ErrNotExist
	}
	return r.header, r.body, nil
}

func TestPckRevocation(t *testing.T) {
	p := newFakePki(t)
	chain := []*x509.Certificate{p.leaf, p.ca}
	if err := checkPckRevocation(chain, p.getter(t), p.root, p.now); err != nil {
		t.Fatalf("clean chain: %v", err)
	}

	p.pckRevoked = true
	if err := checkPckRevocation(chain, p.getter(t), p.root, p.now); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Errorf("revoked leaf: %v", err)
	}
	p.pckRevoked = false

	p.caRevoked = true
	if err := checkPckRevocation(chain, p.getter(t), p.root, p.now); err == nil || !strings.Contains(err.Error(), "issuing CA") {
		t.Errorf("revoked CA: %v", err)
	}
	p.caRevoked = false

	// A stale CRL vouches for nothing.
	p.pckNextUpdate = p.now.Add(-time.Minute)
	if err := checkPckRevocation(chain, p.getter(t), p.root, p.now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired CRL: %v", err)
	}
	p.pckNextUpdate = p.now.Add(24 * time.Hour)

	// A CRL chain that ends at another root is refused.
	other := newFakePki(t)
	if err := checkPckRevocation(chain, p.getter(t), other.root, p.now); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("foreign root: %v", err)
	}
	// A CRL from a different CA than the leaf's issuer is refused.
	if err := checkPckRevocation([]*x509.Certificate{other.leaf, other.ca}, p.getter(t), p.root, p.now); err == nil {
		t.Error("CRL issuer must match the leaf issuer")
	}
	// No CRL at all: fail closed.
	if err := checkPckRevocation(chain, &mapGetter{responses: map[string]mapResponse{}}, p.root, p.now); err == nil {
		t.Error("missing CRL must fail")
	}
	if err := checkPckRevocation(chain[:1], p.getter(t), p.root, p.now); err == nil {
		t.Error("a chain without the issuing CA must fail")
	}
}

// Live: the production quote's PCK chain against Intel's real CRLs (AS_TEST_TDX_QUOTE, network).
func TestPckRevocationLive(t *testing.T) {
	path := os.Getenv("AS_TEST_TDX_QUOTE")
	if path == "" || os.Getenv("SKIP_LIVE_PCS") == "1" {
		t.Skip("AS_TEST_TDX_QUOTE not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	q, err := parseTDXForTest(raw)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parsePEMChain(q)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPckRevocation(certs, getCollateralGetter(), intelSGXRootCA, time.Now()); err != nil {
		t.Fatalf("live revocation check: %v", err)
	}
	t.Logf("live: %s issued by %q not revoked", certs[0].SerialNumber.Text(16), certs[1].Subject.CommonName)
}
