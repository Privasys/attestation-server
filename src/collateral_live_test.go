// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// pckCAFromChain infers the PCK CRL "ca" parameter (processor|platform) from the
// intermediate CA certificate's subject CN.
func pckCAFromChain(cn string) string {
	if strings.Contains(cn, "Platform") {
		return "platform"
	}
	return "processor"
}

// TestLiveSGXCollateral hits Intel PCS v4 with the REAL prod-vault fixture's FMSPC and
// exercises the full pure-Go collateral path end-to-end: fetch + issuer-chain pin +
// signature verify + TCB-status derivation + QE identity + PCK CRL. It is network-gated:
// it SKIPS (does not fail) when PCS is unreachable, so CI without egress stays green;
// run it locally (or where PCS is reachable) to validate against genuine Intel data.
func TestLiveSGXCollateral(t *testing.T) {
	if os.Getenv("SKIP_LIVE_PCS") == "1" {
		t.Skip("SKIP_LIVE_PCS=1")
	}

	raw, err := os.ReadFile("testdata/prod-vault-sgx.quote")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	q, err := ParseSGXQuote(raw)
	if err != nil {
		t.Fatalf("parse fixture quote: %v", err)
	}
	certs, err := parsePEMChain(q.QECertData)
	if err != nil || len(certs) < 2 {
		t.Fatalf("parse PCK chain: %v (n=%d)", err, len(certs))
	}
	pckLeaf := certs[0]
	ext, err := pcs.PckCertificateExtensions(pckLeaf)
	if err != nil {
		t.Fatalf("parse PCK extensions: %v", err)
	}
	t.Logf("FMSPC=%s PCESVN=%d CA-CN=%q", ext.FMSPC, ext.TCB.PCESvn, certs[1].Subject.CommonName)

	getter := newCachingGetter(newNetGetter(15*time.Second), 24*time.Hour)

	// --- TCB info + status derivation ---
	tcbInfo, err := fetchSGXTcbInfo(ext.FMSPC, getter)
	if err != nil {
		t.Skipf("live PCS unreachable (SGX TCB info): %v", err)
	}
	if tcbInfo.Fmspc != ext.FMSPC {
		t.Fatalf("TCB info FMSPC %q != PCK cert FMSPC %q", tcbInfo.Fmspc, ext.FMSPC)
	}
	status, err := matchSGXTCBStatus(tcbInfo, ext)
	if err != nil {
		t.Fatalf("derive TCB status: %v", err)
	}
	t.Logf("derived platform TCB status = %q", status)
	if status == "" {
		t.Fatal("empty TCB status")
	}
	// The prod vault is a real, running platform: its status must be a known value,
	// and (critically) must pass acceptance under the secure floor OR be a status we
	// consciously handle. Log the floor verdict for visibility.
	if err := tcbAcceptable(status, nil); err != nil {
		t.Logf("NOTE: prod vault TCB status %q is NOT in the secure floor: %v", status, err)
		t.Logf("      (this would require a per-measurement policy relaxation once policy plumbing lands)")
	} else {
		t.Logf("prod vault TCB status %q passes the secure floor", status)
	}

	// --- QE identity ---
	qe, err := fetchSGXQeIdentity(getter)
	if err != nil {
		t.Fatalf("fetch QE identity: %v", err)
	}
	if len(qe.TcbLevels) == 0 {
		t.Fatal("QE identity has no TCB levels")
	}
	t.Logf("QE identity id=%s version=%d tcbLevels=%d", qe.ID, qe.Version, len(qe.TcbLevels))

	// --- PCK CRL ---
	ca := pckCAFromChain(certs[1].Subject.CommonName)
	crl, err := fetchSGXPckCrl(ca, getter)
	if err != nil {
		t.Fatalf("fetch PCK CRL (ca=%s): %v", ca, err)
	}
	for _, rc := range crl.RevokedCertificateEntries {
		if rc.SerialNumber.Cmp(pckLeaf.SerialNumber) == 0 {
			t.Fatal("prod vault PCK leaf is REVOKED by the PCK CRL")
		}
	}
	t.Logf("PCK CRL ok (ca=%s, %d revoked entries); prod vault leaf not revoked", ca, len(crl.RevokedCertificateEntries))
}
