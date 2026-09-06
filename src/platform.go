// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Platform identity: which physical machine produced the evidence.
//
// A quote that verifies proves that a genuine TEE with the reported
// measurements signed it, not which machine it came from: any platform
// whose attestation key has not been revoked passes. Relying parties that
// know which machines they operate can pin them. For Intel SGX and TDX the
// PCK certificate embedded in the quote carries the platform's identifiers
// in its SGX extension (OID 1.2.840.113741.1.13.1): the PPID (.1) on every
// PCK certificate, and the Platform Instance ID (.6) on certificates issued
// by the Intel SGX PCK Platform CA (multi-package platforms). For AMD SEV-SNP
// the report's CHIP_ID identifies the die. The identifiers are reported in
// every verification response, and a request may carry an allow-list that the
// verification must satisfy (status PLATFORM_NOT_ALLOWED otherwise).

var (
	oidSgxExtension      = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidSgxPPID           = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 1}
	oidSgxFMSPC          = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
	oidSgxPlatformInstID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 6}
)

// PlatformIdentity is the set of hardware identifiers found in the evidence,
// lowercase hex. Intel: PPID always, PlatformInstanceID on Platform CA
// certificates, FMSPC for reference. AMD: ChipID.
type PlatformIdentity struct {
	PPID               string `json:"ppid,omitempty"`
	PlatformInstanceID string `json:"platformInstanceId,omitempty"`
	FMSPC              string `json:"fmspc,omitempty"`
	ChipID             string `json:"chipId,omitempty"`
}

// ID is the identifier an allow-list entry is matched against: the Platform
// Instance ID when the PCK certificate carries one, else the PPID, else the
// SEV-SNP CHIP_ID. Empty when nothing identifies the platform.
func (p *PlatformIdentity) ID() string {
	if p == nil {
		return ""
	}
	switch {
	case p.PlatformInstanceID != "":
		return p.PlatformInstanceID
	case p.PPID != "":
		return p.PPID
	default:
		return p.ChipID
	}
}

// parsePlatformIdentity reads the SGX extension of a PCK leaf certificate.
func parsePlatformIdentity(leaf *x509.Certificate) (*PlatformIdentity, error) {
	var raw []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidSgxExtension) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("PCK certificate has no SGX extension (%s)", oidSgxExtension)
	}
	var entries []asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &entries)
	if err != nil {
		return nil, fmt.Errorf("SGX extension: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("SGX extension: trailing bytes")
	}
	p := &PlatformIdentity{}
	for _, e := range entries {
		var entry struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(e.FullBytes, &entry); err != nil {
			return nil, fmt.Errorf("SGX extension entry: %w", err)
		}
		octets := func(name string, size int) (string, error) {
			var b []byte
			if _, err := asn1.Unmarshal(entry.Value.FullBytes, &b); err != nil {
				return "", fmt.Errorf("SGX extension %s: %w", name, err)
			}
			if len(b) != size {
				return "", fmt.Errorf("SGX extension %s: %d bytes, want %d", name, len(b), size)
			}
			return hex.EncodeToString(b), nil
		}
		switch {
		case entry.Type.Equal(oidSgxPPID):
			if p.PPID, err = octets("PPID", 16); err != nil {
				return nil, err
			}
		case entry.Type.Equal(oidSgxFMSPC):
			if p.FMSPC, err = octets("FMSPC", 6); err != nil {
				return nil, err
			}
		case entry.Type.Equal(oidSgxPlatformInstID):
			if p.PlatformInstanceID, err = octets("Platform Instance ID", 16); err != nil {
				return nil, err
			}
		}
	}
	if p.PPID == "" {
		return nil, fmt.Errorf("PCK certificate SGX extension carries no PPID")
	}
	return p, nil
}

// platformIdentityFromChain reads the PCK leaf of a PEM chain as embedded in a
// DCAP quote's certification data.
func platformIdentityFromChain(pemChain []byte) (*PlatformIdentity, error) {
	certs, err := parsePEMChain(pemChain)
	if err != nil {
		return nil, fmt.Errorf("PCK chain: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("PCK chain: no certificate")
	}
	return parsePlatformIdentity(certs[0])
}

// normalizePlatformID lowercases a hex identifier and drops separators so that
// "C055FC7B-49BD-..." and "c055fc7b49bd..." compare equal.
func normalizePlatformID(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", ":", "", " ", "").Replace(strings.TrimSpace(s)))
}

// platformAllowed checks the evidence's platform identity against a
// relying-party allow-list. An empty list allows every platform. A non-empty
// list with no identity in the evidence fails closed.
func platformAllowed(p *PlatformIdentity, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	id := normalizePlatformID(p.ID())
	if id == "" {
		return fmt.Errorf("evidence carries no platform identity to match the allow-list")
	}
	for _, a := range allowed {
		if normalizePlatformID(a) == id {
			return nil
		}
	}
	return fmt.Errorf("platform %s is not in the allow-list (%d entries)", id, len(allowed))
}
