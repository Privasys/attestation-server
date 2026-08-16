// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// mockGetter returns a canned response, or an error once failing is set.
type mockGetter struct {
	header  map[string][]string
	body    []byte
	calls   int
	failing bool
}

func (m *mockGetter) Get(string) (map[string][]string, []byte, error) {
	m.calls++
	if m.failing {
		return nil, nil, fmt.Errorf("simulated PCS outage")
	}
	return m.header, m.body, nil
}

func TestCachingGetter_GraceWindow(t *testing.T) {
	base := &mockGetter{header: map[string][]string{"X": {"v"}}, body: []byte("collateral")}
	clock := time.Unix(1_700_000_000, 0)
	c := newCachingGetter(base, 24*time.Hour)
	c.now = func() time.Time { return clock }

	// First fetch succeeds and populates the cache.
	if _, body, err := c.Get("u"); err != nil || string(body) != "collateral" {
		t.Fatalf("initial fetch: body=%q err=%v", body, err)
	}

	// PCS goes down; within grace, cached collateral is served.
	base.failing = true
	clock = clock.Add(12 * time.Hour)
	if _, body, err := c.Get("u"); err != nil || string(body) != "collateral" {
		t.Fatalf("within grace should serve cache: body=%q err=%v", body, err)
	}

	// Past the grace window, it must fail closed.
	clock = clock.Add(24 * time.Hour) // now 36h since fetch, grace is 24h
	if _, _, err := c.Get("u"); err == nil {
		t.Fatal("past grace window must fail closed, got success")
	}
}

func TestCachingGetter_StrictFailClosed(t *testing.T) {
	base := &mockGetter{body: []byte("x")}
	clock := time.Unix(1_700_000_000, 0)
	c := newCachingGetter(base, 0) // grace 0 == strict fail-closed
	c.now = func() time.Time { return clock }
	if _, _, err := c.Get("u"); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	base.failing = true
	clock = clock.Add(time.Second)
	if _, _, err := c.Get("u"); err == nil {
		t.Fatal("grace 0 must fail closed immediately on outage")
	}
}

func TestVerifyIssuerChain_RejectsForeignRoot(t *testing.T) {
	// A self-signed cert that is NOT the pinned Intel root must be rejected as both
	// the issuer-chain root and (therefore) as a signing anchor.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Not Intel SGX Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	foreign, _ := x509.ParseCertificate(der)

	if err := verifyIssuerChain(foreign, foreign); err == nil {
		t.Fatal("verifyIssuerChain accepted a foreign (non-pinned) root")
	}
}
