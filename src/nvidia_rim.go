// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// NVIDIA GPU firmware/VBIOS measurement matching against pinned golden values.
//
// The golden values (see golden_gh100.go) are extracted OFFLINE by rim_extract.py
// from NVIDIA's driver + VBIOS Reference Integrity Manifests (RIMs), each an
// ISO-19770 SWID document signed with XML-DSig. Go has no safe XML-DSig
// verifier, so we do NOT parse RIMs at runtime; instead the offline tool
// verifies the RIM signatures against the pinned NVIDIA RIM root, applies
// nvtrust's combine rules (active driver ∪ active VBIOS measurements), and bakes
// the result into a Go table keyed by (driver, VBIOS). This file re-derives the
// runtime measurements from the signed SPDM report and compares them, replicating
// nvtrust's verifier.Verifier.verify exactly.
//
// MeasurementsVerified is set true only when a golden table exists for the
// report's exact driver+VBIOS AND every active golden index matches. Any gap
// (unknown driver/VBIOS, parse failure, mismatch) leaves it false — fail closed.

// goldenMeasurement is one golden measurement index: its byte size, which RIM it
// came from ("Driver"/"Firmware"), and the accepted alternative hex values.
type goldenMeasurement struct {
	Size   int
	Source string
	Values []string
}

// goldenTable is the combined active golden measurement set for one driver+VBIOS.
type goldenTable struct {
	Driver       string
	VBIOS        string
	Measurements map[int]goldenMeasurement
}

// goldenTables is the registry of pinned golden sets, looked up by driver+VBIOS.
var goldenTables = []*goldenTable{&goldenGH100}

// SPDM GET_MEASUREMENTS request length prepended to the NVML attestation report.
const spdmRequestLen = 37

// Opaque data field ids (DMTF/NVIDIA) we need for RIM matching.
const (
	opaqueDriverVersion = 3
	opaqueVBIOSVersion  = 6
	opaqueNVDEC0Status  = 11
)

// nvdec0Disabled is the NVDEC0 status byte meaning the engine is disabled; when
// disabled, golden measurement index 35 is not compared (nvtrust is_msr_35_valid).
const nvdec0Disabled = 0x55

// parsedGPUReport holds the runtime data re-derived from the signed SPDM report.
type parsedGPUReport struct {
	// runtime[i] is the hex measurement value for SPDM block index i+1.
	runtime      []string
	driver       string
	vbios        string
	nvdec0Status int // -1 when absent
}

// parseGPUReportMeasurements parses the NVML attestation report (SPDM request ‖
// response) into runtime measurements and the opaque driver/VBIOS/NVDEC fields.
// The report is already signature-verified by the caller.
func parseGPUReportMeasurements(report []byte) (*parsedGPUReport, error) {
	if len(report) <= spdmRequestLen+8 {
		return nil, fmt.Errorf("report too short (%d bytes)", len(report))
	}
	resp := report[spdmRequestLen:]
	numBlocks := int(resp[4])
	recLen := int(resp[5]) | int(resp[6])<<8 | int(resp[7])<<16 // 3-byte LE
	recStart := 8
	if recStart+recLen > len(resp) {
		return nil, fmt.Errorf("measurement record overruns response (len=%d, have=%d)", recLen, len(resp)-recStart)
	}
	record := resp[recStart : recStart+recLen]

	runtime := make([]string, numBlocks)
	bi := 0
	for n := 0; n < numBlocks; n++ {
		if bi+4 > len(record) {
			return nil, fmt.Errorf("truncated measurement block header at %d", bi)
		}
		index := int(record[bi])
		spec := record[bi+1]
		if spec != 1 {
			return nil, fmt.Errorf("measurement block %d not DMTF (spec=%d)", index, spec)
		}
		mSize := int(binary.LittleEndian.Uint16(record[bi+2 : bi+4]))
		bi += 4
		if bi+mSize > len(record) {
			return nil, fmt.Errorf("truncated measurement block %d value", index)
		}
		mData := record[bi : bi+mSize]
		bi += mSize
		// DMTF measurement: type(1) size(2 LE) value(size).
		if len(mData) < 3 {
			return nil, fmt.Errorf("measurement block %d DMTF too short", index)
		}
		vSize := int(binary.LittleEndian.Uint16(mData[1:3]))
		if 3+vSize > len(mData) {
			return nil, fmt.Errorf("measurement block %d DMTF value overruns", index)
		}
		if index < 1 || index > numBlocks {
			return nil, fmt.Errorf("measurement block index %d out of range", index)
		}
		runtime[index-1] = fmt.Sprintf("%x", mData[3:3+vSize])
	}
	if bi != len(record) {
		return nil, fmt.Errorf("measurement record trailing bytes (%d of %d)", bi, len(record))
	}

	// Opaque data follows: nonce(32) at recStart+recLen, then opaqueLen(2 LE),
	// then opaque bytes.
	nonceOff := recStart + recLen
	if nonceOff+34 > len(resp) {
		return nil, fmt.Errorf("response too short for opaque header")
	}
	opaqueLen := int(binary.LittleEndian.Uint16(resp[nonceOff+32 : nonceOff+34]))
	opaqueStart := nonceOff + 34
	if opaqueStart+opaqueLen > len(resp) {
		return nil, fmt.Errorf("opaque data overruns response")
	}
	fields := parseOpaqueData(resp[opaqueStart : opaqueStart+opaqueLen])

	out := &parsedGPUReport{runtime: runtime, nvdec0Status: -1}
	if v, ok := fields[opaqueDriverVersion]; ok {
		out.driver = strings.ToLower(strings.Trim(strings.TrimSpace(cString(v)), "\x00"))
	}
	if v, ok := fields[opaqueVBIOSVersion]; ok {
		out.vbios = formatVBIOSVersion(v)
	}
	if v, ok := fields[opaqueNVDEC0Status]; ok && len(v) > 0 {
		out.nvdec0Status = int(v[0])
	}
	return out, nil
}

// parseOpaqueData parses the SPDM opaque data TLV stream: repeated
// [DataType u16-LE][DataSize u16-LE][Data]. Returns a map of type id -> bytes.
func parseOpaqueData(data []byte) map[int][]byte {
	fields := make(map[int][]byte)
	i := 0
	for i+4 <= len(data) {
		dtype := int(binary.LittleEndian.Uint16(data[i : i+2]))
		dsize := int(binary.LittleEndian.Uint16(data[i+2 : i+4]))
		i += 4
		if i+dsize > len(data) {
			break
		}
		fields[dtype] = data[i : i+dsize]
		i += dsize
	}
	return fields
}

// cString returns the bytes up to the first NUL as a string.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// formatVBIOSVersion mirrors nvtrust utils.format_vbios_version: reverse the
// bytes to a hex string, swap the trailing byte to the front-of-tail, and
// dot-join into xx.xx.xx.xx.xx. Produces e.g. "96.00.cf.00.01".
func formatVBIOSVersion(version []byte) string {
	// value = reversed(version).hex()
	rev := make([]byte, len(version))
	for i, b := range version {
		rev[len(version)-1-i] = b
	}
	value := fmt.Sprintf("%x", rev)
	if len(value) < 4 {
		return value
	}
	half := len(value) / 2
	temp := value[half:] + value[half-2:half]
	var sb strings.Builder
	idx := 0
	for i := 0; i+2 < len(temp)-1; i += 2 {
		sb.WriteString(temp[i : i+2])
		sb.WriteByte('.')
		idx = i + 2
	}
	sb.WriteString(temp[idx : idx+2])
	return strings.ToLower(sb.String())
}

// matchGoldenMeasurements re-derives the runtime measurements from the signed
// report and compares them against the pinned golden table for the report's
// driver+VBIOS. Returns (true, "") only when a matching table exists and every
// active golden index matches; otherwise (false, reason) — fail closed.
func matchGoldenMeasurements(report []byte) (bool, string) {
	p, err := parseGPUReportMeasurements(report)
	if err != nil {
		return false, fmt.Sprintf("parse measurements: %v", err)
	}
	var table *goldenTable
	for _, t := range goldenTables {
		if strings.EqualFold(t.Driver, p.driver) && strings.EqualFold(t.VBIOS, p.vbios) {
			table = t
			break
		}
	}
	if table == nil {
		return false, fmt.Sprintf("no pinned golden RIM for driver %q vbios %q", p.driver, p.vbios)
	}

	msr35Valid := p.nvdec0Status != nvdec0Disabled
	var mismatched []int
	compared := 0
	for idx, g := range table.Measurements {
		if idx == 35 && !msr35Valid {
			continue
		}
		compared++
		if idx < 0 || idx >= len(p.runtime) {
			mismatched = append(mismatched, idx)
			continue
		}
		rt := p.runtime[idx]
		ok := false
		for _, v := range g.Values {
			if v == rt && g.Size == len(rt)/2 {
				ok = true
				break
			}
		}
		if !ok {
			mismatched = append(mismatched, idx)
		}
	}
	if len(mismatched) > 0 {
		return false, fmt.Sprintf("runtime measurements do not match golden at indexes %v", mismatched)
	}
	return true, fmt.Sprintf("all %d active golden measurements matched (driver %s, vbios %s)", compared, table.Driver, table.VBIOS)
}
