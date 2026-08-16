// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"testing"

	"github.com/google/go-tdx-guest/pcs"
)

// comps builds a 16-component SGX TCB component slice with every component == v.
func comps(v byte) []pcs.TcbComponent {
	out := make([]pcs.TcbComponent, 16)
	for i := range out {
		out[i] = pcs.TcbComponent{Svn: v}
	}
	return out
}

// cpuSvn builds a 16-byte CPU-SVN with every component == v.
func cpuSvn(v byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = v
	}
	return b
}

func ext(cpu byte, pce uint16) *pcs.PckExtensions {
	return &pcs.PckExtensions{TCB: pcs.PckCertTCB{CPUSvnComponents: cpuSvn(cpu), PCESvn: pce}}
}

// tcbInfo with levels ordered newest-first (highest SVN first), as Intel serves them.
func tcbInfoFixture() pcs.TcbInfo {
	return pcs.TcbInfo{TcbLevels: []pcs.TcbLevel{
		{Tcb: pcs.Tcb{SgxTcbcomponents: comps(10), Pcesvn: 10}, TcbStatus: pcs.TcbComponentStatusUpToDate},
		{Tcb: pcs.Tcb{SgxTcbcomponents: comps(8), Pcesvn: 8}, TcbStatus: pcs.TcbComponentStatusSwHardeningNeeded},
		{Tcb: pcs.Tcb{SgxTcbcomponents: comps(5), Pcesvn: 5}, TcbStatus: pcs.TcbComponentStatusOutOfDate},
		{Tcb: pcs.Tcb{SgxTcbcomponents: comps(2), Pcesvn: 2}, TcbStatus: pcs.TcbComponentStatusRevoked},
	}}
}

func TestMatchSGXTCBStatus(t *testing.T) {
	info := tcbInfoFixture()
	cases := []struct {
		name string
		cpu  byte
		pce  uint16
		want TCBStatus
	}{
		{"fully patched -> UpToDate", 12, 12, pcs.TcbComponentStatusUpToDate},
		{"exactly top level -> UpToDate", 10, 10, pcs.TcbComponentStatusUpToDate},
		{"one below top -> SWHardeningNeeded", 9, 9, pcs.TcbComponentStatusSwHardeningNeeded},
		{"mid -> OutOfDate", 6, 6, pcs.TcbComponentStatusOutOfDate},
		{"low -> Revoked", 2, 2, pcs.TcbComponentStatusRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matchSGXTCBStatus(info, ext(tc.cpu, tc.pce))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMatchSGXTCBStatus_PCESvnGates(t *testing.T) {
	info := tcbInfoFixture()
	// CPU components are top-tier but PCESVN is low: must NOT match the top level;
	// it should fall to the highest level whose PCESVN it also satisfies.
	got, err := matchSGXTCBStatus(info, ext(12, 8))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != pcs.TcbComponentStatusSwHardeningNeeded {
		t.Fatalf("status = %q, want SWHardeningNeeded (PCESVN should gate out the top level)", got)
	}
}

func TestMatchSGXTCBStatus_NoMatch(t *testing.T) {
	info := tcbInfoFixture()
	// Below every level -> no match is an error (never silently "accept").
	if _, err := matchSGXTCBStatus(info, ext(1, 1)); err == nil {
		t.Fatal("expected no-match error for a platform below every TCB level")
	}
}

func TestTCBAcceptable_Floor(t *testing.T) {
	if err := tcbAcceptable(pcs.TcbComponentStatusUpToDate, nil); err != nil {
		t.Fatalf("UpToDate must be accepted by the floor: %v", err)
	}
	if err := tcbAcceptable(pcs.TcbComponentStatusSwHardeningNeeded, nil); err != nil {
		t.Fatalf("SWHardeningNeeded must be accepted by the floor: %v", err)
	}
	if err := tcbAcceptable(pcs.TcbComponentStatusOutOfDate, nil); err == nil {
		t.Fatal("OutOfDate must be rejected by the floor (no relaxation)")
	}
	if err := tcbAcceptable(pcs.TcbComponentStatusConfigurationNeeded, nil); err == nil {
		t.Fatal("ConfigurationNeeded must be rejected by the floor (no relaxation)")
	}
}

func TestTCBAcceptable_PolicyRelaxes(t *testing.T) {
	relax := map[TCBStatus]bool{pcs.TcbComponentStatusOutOfDate: true}
	if err := tcbAcceptable(pcs.TcbComponentStatusOutOfDate, relax); err != nil {
		t.Fatalf("policy relaxation should accept OutOfDate: %v", err)
	}
	// Relaxing OutOfDate must not implicitly accept ConfigurationNeeded.
	if err := tcbAcceptable(pcs.TcbComponentStatusConfigurationNeeded, relax); err == nil {
		t.Fatal("relaxing OutOfDate must not accept ConfigurationNeeded")
	}
}

func TestTCBAcceptable_RevokedNeverAcceptable(t *testing.T) {
	// Even a policy that explicitly tries to allow Revoked must be refused.
	relax := map[TCBStatus]bool{pcs.TcbComponentStatusRevoked: true}
	if err := tcbAcceptable(pcs.TcbComponentStatusRevoked, relax); err == nil {
		t.Fatal("Revoked must be non-overridable — a policy allowing it must still fail")
	}
}
