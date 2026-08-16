// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"fmt"

	"github.com/google/go-tdx-guest/pcs"
)

// TCBStatus is Intel's platform TCB status for a quote, derived by comparing the
// PCK certificate's TCB against Intel PCS TCB info. Values are the pcs constants
// (UpToDate, SWHardeningNeeded, ConfigurationNeeded, OutOfDate, Revoked, …).
type TCBStatus = pcs.TcbComponentStatus

// matchSGXTCBStatus derives the platform TCB status for an SGX PCK certificate.
// It finds the highest TCB level in tcbInfo whose SGX components AND PCESVN are all
// <= the PCK certificate's, and returns that level's status. Intel orders TcbLevels
// newest-first, so the first match is authoritative. This mirrors go-tdx-guest's
// getMatchingTcbLevel (the reference) minus the TDX-only component comparison — the
// SGX quote has no TEE TCB SVN.
func matchSGXTCBStatus(tcbInfo pcs.TcbInfo, ext *pcs.PckExtensions) (TCBStatus, error) {
	cpu := ext.TCB.CPUSvnComponents
	for _, lvl := range tcbInfo.TcbLevels {
		if sgxComponentsGE(cpu, lvl.Tcb.SgxTcbcomponents) && ext.TCB.PCESvn >= lvl.Tcb.Pcesvn {
			return lvl.TcbStatus, nil
		}
	}
	return "", fmt.Errorf("no TCB level in Intel TCB info matches the platform PCK certificate")
}

// sgxComponentsGE reports whether every one of the PCK certificate's 16 SGX CPU-SVN
// component bytes is >= the corresponding TCB-level component. A platform is "at or
// above" a TCB level only when it satisfies EVERY component (Intel's rule).
func sgxComponentsGE(cpuSvn []byte, comps []pcs.TcbComponent) bool {
	if len(cpuSvn) < len(comps) {
		return false
	}
	for i, c := range comps {
		if cpuSvn[i] < c.Svn {
			return false
		}
	}
	return true
}

// secureTCBFloor is the set of TCB statuses accepted by default, with no per-policy
// relaxation. UpToDate is fully patched. SWHardeningNeeded means the residual issues
// are mitigated by enclave software mitigations (which the Privasys enclaves apply),
// so it is safe to accept — this is also the most common real-world status, so
// rejecting it would break the fleet. Everything else (ConfigurationNeeded, OutOfDate,
// their combinations) requires an explicit, auditable policy relaxation. Revoked is
// never acceptable (handled separately, non-overridable).
var secureTCBFloor = map[TCBStatus]bool{
	pcs.TcbComponentStatusUpToDate:          true,
	pcs.TcbComponentStatusSwHardeningNeeded: true,
}

// tcbAcceptable reports whether a derived TCB status passes acceptance.
//
//   - Revoked is NEVER acceptable, regardless of policy (hard-coded — a revoked TCB
//     is known-broken/compromised, not merely behind).
//   - Statuses in the secure floor are always accepted.
//   - Any other status is accepted only if the per-measurement policy explicitly
//     relaxes to include it (relax[status] == true). The policy can only ADD to the
//     floor, never remove from it.
//
// relax may be nil (no relaxation → floor only).
func tcbAcceptable(status TCBStatus, relax map[TCBStatus]bool) error {
	if status == pcs.TcbComponentStatusRevoked {
		return fmt.Errorf("TCB status Revoked is never acceptable")
	}
	if secureTCBFloor[status] {
		return nil
	}
	if relax[status] {
		return nil
	}
	return fmt.Errorf("TCB status %q rejected: not in the secure floor and no policy relaxation authorises it", status)
}
