// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The fixture is the PCK leaf of a production TDX quote: issued by the Intel
// SGX PCK Platform CA, so it carries a Platform Instance ID as well as a PPID.
func loadPlatformLeaf(t *testing.T) *PlatformIdentity {
	t.Helper()
	pemLeaf, err := os.ReadFile("testdata/pck-platform-leaf.pem")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := platformIdentityFromChain(pemLeaf)
	if err != nil {
		t.Fatalf("platform identity: %v", err)
	}
	return p
}

func TestPlatformIdentityFromPlatformCALeaf(t *testing.T) {
	p := loadPlatformLeaf(t)
	if p.PPID != "414afbe506e8ac361add41f3133aab6f" {
		t.Errorf("PPID = %s", p.PPID)
	}
	if p.PlatformInstanceID != "c055fc7b49bd4185dda796bf1795af32" {
		t.Errorf("PlatformInstanceID = %s", p.PlatformInstanceID)
	}
	if p.FMSPC != "00806f050000" {
		t.Errorf("FMSPC = %s", p.FMSPC)
	}
	// The Platform Instance ID is the identifier of record when present.
	if p.ID() != p.PlatformInstanceID {
		t.Errorf("ID() = %s, want the Platform Instance ID", p.ID())
	}
}

func TestPlatformIdentityFromProcessorCAQuote(t *testing.T) {
	raw, err := os.ReadFile("testdata/prod-vault-sgx.quote")
	if err != nil {
		t.Skipf("fixture: %v", err)
	}
	q, err := ParseSGXQuote(raw)
	if err != nil {
		t.Fatalf("parse quote: %v", err)
	}
	p, err := platformIdentityFromChain(q.QECertData)
	if err != nil {
		t.Fatalf("platform identity: %v", err)
	}
	if len(p.PPID) != 32 {
		t.Errorf("PPID = %q", p.PPID)
	}
	if p.ID() == "" {
		t.Error("ID() empty")
	}
	if p.PlatformInstanceID == "" && p.ID() != p.PPID {
		t.Errorf("without a Platform Instance ID the PPID is the identifier, got %s", p.ID())
	}
}

func TestPlatformAllowed(t *testing.T) {
	p := loadPlatformLeaf(t)
	if err := platformAllowed(p, nil); err != nil {
		t.Errorf("empty list must allow: %v", err)
	}
	for _, ok := range []string{
		p.PlatformInstanceID,
		strings.ToUpper(p.PlatformInstanceID),
		"c055fc7b-49bd-4185-dda7-96bf1795af32",
	} {
		if err := platformAllowed(p, []string{"deadbeef", ok}); err != nil {
			t.Errorf("%s should be allowed: %v", ok, err)
		}
	}
	// The PPID does not stand in for the Platform Instance ID when the certificate carries one.
	if err := platformAllowed(p, []string{p.PPID}); err == nil {
		t.Error("PPID must not match when a Platform Instance ID is present")
	}
	if err := platformAllowed(p, []string{"0000"}); err == nil || !strings.Contains(err.Error(), "not in the allow-list") {
		t.Errorf("unexpected: %v", err)
	}
	// No identity at all fails closed against a non-empty list.
	if err := platformAllowed(&PlatformIdentity{}, []string{"x"}); err == nil {
		t.Error("empty identity must fail against a non-empty list")
	}
	if err := platformAllowed(nil, []string{"x"}); err == nil {
		t.Error("nil identity must fail against a non-empty list")
	}
	snp := &PlatformIdentity{ChipID: "ab" + strings.Repeat("00", 63)}
	if err := platformAllowed(snp, []string{snp.ChipID}); err != nil {
		t.Errorf("chip id: %v", err)
	}
}

// End to end through the HTTP handler with a real TDX quote, when one is
// supplied (AS_TEST_TDX_QUOTE=<path to a raw quote>): the response reports the
// platform identity, an allow-list naming it passes, another one fails with
// PLATFORM_NOT_ALLOWED.
func TestVerifyHandlerTDXAllowList(t *testing.T) {
	path := os.Getenv("AS_TEST_TDX_QUOTE")
	if path == "" {
		t.Skip("AS_TEST_TDX_QUOTE not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read quote: %v", err)
	}
	post := func(allowed []string) VerifyResponse {
		body, _ := json.Marshal(VerifyRequest{Quote: base64.StdEncoding.EncodeToString(raw), AllowedPlatformIds: allowed})
		rec := httptest.NewRecorder()
		verifyHandler(rec, httptest.NewRequest("POST", "/api/verify", bytes.NewReader(body)))
		var resp VerifyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response: %v: %s", err, rec.Body.String())
		}
		return resp
	}
	first := post(nil)
	if !first.Success || first.Platform == nil || first.Platform.ID() == "" {
		t.Fatalf("baseline: %+v", first)
	}
	t.Logf("platform: %+v", *first.Platform)
	if ok := post([]string{"0000", strings.ToUpper(first.Platform.ID())}); !ok.Success {
		t.Errorf("allow-list naming the platform must pass: %+v", ok)
	}
	if bad := post([]string{"00112233445566778899aabbccddeeff"}); bad.Success || bad.Status != "PLATFORM_NOT_ALLOWED" || bad.Platform == nil {
		t.Errorf("allow-list without the platform must fail closed: %+v", bad)
	}
}
