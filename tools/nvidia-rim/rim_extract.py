#!/usr/bin/env python3
"""Offline NVIDIA GPU golden-measurement extractor.

Faithfully replicates the nvtrust Local GPU Verifier RIM logic so we can bake a
pinned Go golden-measurement table for a specific (driver, VBIOS) pair:

  1. Parse the real captured attestation report -> opaque data (project,
     project_sku, chip_sku, vbios_version, driver_version, NVDEC0 status) and
     the runtime SPDM measurement record.
  2. Fetch the driver + VBIOS RIMs from the NVIDIA RIM service.
  3. Verify each RIM's XML-DSig against the pinned NVIDIA RIM root cert.
  4. Parse golden measurements; combine active driver + active VBIOS (nvtrust
     generate_golden_measurement_list rules).
  5. Compare the combined golden set against the runtime measurements to PROVE
     the table is correct for this GPU (end-to-end, like nvtrust verify()).
  6. Emit a Go golden table.

Requires: signxml, lxml (pip install signxml lxml). Needs the NVIDIA RIM root
cert, shipped with nvtrust at
  guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_RIM_root.pem

Usage:
  python3 rim_extract.py \
      --report /path/to/gpu_atst_report.bin \
      --rim-root /path/to/verifier_RIM_root.pem \
      --out ../../src/golden_gh100.go

Re-run whenever NVIDIA ships a new GPU driver or VBIOS: the golden table is
pinned to one exact (driver, VBIOS) pair. Capture a fresh report from a genuine
CC GPU on that driver/VBIOS (the enclave's gpu-attest writes the envelope; its
TLV 0x02 field is the report), then regenerate.
"""
import argparse
import base64
import json
import sys
import urllib.request
from lxml import etree
from signxml import XMLVerifier

RIM_SERVICE = "https://rim.attestation.nvidia.com/v1/rim/"
SWID_NS = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"

REQ_LEN = 37  # SPDM GET_MEASUREMENTS request prepended to the report

OPAQUE = {
    3: "DRIVER_VERSION", 4: "GPU_INFO", 5: "SKU", 6: "VBIOS_VERSION",
    7: "MANUFACTURER_ID", 11: "NVDEC0_STATUS", 12: "MSRSCNT", 14: "BOARD_ID",
    15: "CHIP_SKU", 16: "CHIP_SKU_MOD", 17: "PROJECT", 18: "PROJECT_SKU",
    19: "PROJECT_SKU_MOD", 20: "FWID", 34: "OPAQUE_DATA_VERSION",
}
NVDEC_DISABLED = 0x55


def le(b):
    return int.from_bytes(b, "little")


def format_vbios_version(version: bytes) -> str:
    # nvtrust utils.format_vbios_version: reverse to hex, swap halves, dot-join.
    value = version[::-1].hex()
    temp = value[len(value) // 2:] + value[len(value) // 2 - 2: len(value) // 2]
    out, idx = "", 0
    for i in range(0, len(temp) - 2, 2):
        out += temp[i:i + 2] + "."
        idx = i + 2
    out += temp[idx:idx + 2]
    return out


def parse_opaque(data: bytes) -> dict:
    fields, i = {}, 0
    while i < len(data):
        dtype = le(data[i:i + 2]); i += 2
        dsize = le(data[i:i + 2]); i += 2
        val = data[i:i + dsize]; i += dsize
        fields[OPAQUE.get(dtype, dtype)] = val
    return fields


def parse_response(report: bytes):
    """Split report into request+response, return (response, opaque_fields,
    runtime_measurements[list, 0-based], nvdec_status_byte)."""
    resp = report[REQ_LEN:]
    num_blocks = resp[4]
    rec_len = le(resp[5:8])
    record = resp[8:8 + rec_len]
    nonce_off = 8 + rec_len
    opaque_len = le(resp[nonce_off + 32: nonce_off + 34])
    opaque = resp[nonce_off + 34: nonce_off + 34 + opaque_len]

    # Parse measurement record blocks.
    runtime = [None] * num_blocks
    bi = 0
    for _ in range(num_blocks):
        index = record[bi]; bi += 1
        spec = record[bi]; bi += 1
        assert spec == 1, "measurement block not DMTF"
        msize = le(record[bi:bi + 2]); bi += 2
        mdata = record[bi:bi + msize]; bi += msize
        # DMTF measurement: type(1) size(2 LE) value(size)
        dsize = le(mdata[1:3])
        value = mdata[3:3 + dsize]
        runtime[index - 1] = value.hex()
    assert bi == len(record), "measurement record parse length mismatch"

    fields = parse_opaque(opaque)
    nvdec = fields.get("NVDEC0_STATUS", b"")
    nvdec_status = nvdec[0] if nvdec else None
    return resp, fields, runtime, nvdec_status


def fetch_rim(file_id: str) -> str:
    url = RIM_SERVICE + file_id
    with urllib.request.urlopen(url, timeout=30) as r:
        obj = json.loads(r.read())
    return base64.b64decode(obj["rim"]).decode("utf-8")


def verify_xmldsig(rim_xml: str, name: str, rim_root: str):
    root = etree.fromstring(rim_xml.encode())
    verified = XMLVerifier().verify(root, ca_pem_file=rim_root).signed_xml
    if verified is None:
        raise SystemExit(f"{name} RIM XML-DSig verification FAILED")
    print(f"  [{name}] XML-DSig verified against pinned NVIDIA RIM root")
    return verified


def parse_golden(verified_root, name: str) -> dict:
    """Return {index: {'values':[hex...], 'size':int, 'active':bool}} from a
    signxml-verified RIM root, mirroring rim.parse_measurements."""
    payload = None
    for el in verified_root.iter():
        if el.tag.endswith("}Payload") or el.tag.endswith("Payload"):
            payload = el
            break
    if payload is None:
        raise SystemExit(f"{name}: no Payload")
    out = {}
    for child in payload:
        attrib = {etree.QName(k).localname if "{" in k else k: v for k, v in child.attrib.items()}
        active = attrib["active"] != "False"
        index = int(attrib["index"])
        alts = int(attrib["alternatives"])
        values = [attrib[f"Hash{i}"] for i in range(alts)]
        out[index] = {"values": [v.lower() for v in values], "size": int(attrib["size"]),
                      "active": active, "alternatives": alts}
    return out


def combine(driver_g, vbios_g):
    """nvtrust generate_golden_measurement_list: active driver + active vbios,
    error on active-index conflict."""
    golden = {}
    for idx, m in driver_g.items():
        if m["active"]:
            golden[idx] = {**m, "source": "Driver"}
    for idx, m in vbios_g.items():
        if m["active"] and idx in golden:
            raise SystemExit(f"active measurement index conflict at {idx}")
        if m["active"]:
            golden[idx] = {**m, "source": "Firmware"}
    return golden


def main():
    ap = argparse.ArgumentParser(description="Extract pinned NVIDIA GPU golden measurements from signed RIMs.")
    ap.add_argument("--report", required=True, help="path to a captured SPDM attestation report (envelope TLV 0x02)")
    ap.add_argument("--rim-root", required=True, help="path to the NVIDIA RIM root cert (nvtrust verifier_RIM_root.pem)")
    ap.add_argument("--out", default="golden_gh100.go", help="output Go file for the golden table")
    args = ap.parse_args()

    report = open(args.report, "rb").read()
    print(f"report: {len(report)} bytes")
    resp, fields, runtime, nvdec_status = parse_response(report)

    def s(key):
        return fields.get(key, b"").decode("ascii", "replace").strip().strip("\x00")

    project = s("PROJECT").upper()
    project_sku = s("PROJECT_SKU").upper()
    chip_sku = s("CHIP_SKU").upper()
    driver_version = s("DRIVER_VERSION").lower()
    vbios_version = format_vbios_version(fields.get("VBIOS_VERSION", b""))
    vbios_id = vbios_version.replace(".", "").upper()
    is_msr35_valid = nvdec_status != NVDEC_DISABLED

    print(f"project={project} project_sku={project_sku} chip_sku={chip_sku}")
    print(f"driver={driver_version} vbios={vbios_version} nvdec_status={hex(nvdec_status) if nvdec_status is not None else None} msr35_valid={is_msr35_valid}")
    print(f"runtime measurements: {len(runtime)} blocks")

    driver_rim_id = f"NV_GPU_DRIVER_GH100_{driver_version}"
    vbios_rim_id = f"NV_GPU_VBIOS_{project}_{project_sku}_{chip_sku}_{vbios_id}"
    print(f"driver_rim_id={driver_rim_id}")
    print(f"vbios_rim_id={vbios_rim_id}")

    print("Fetching + verifying RIMs:")
    driver_xml = fetch_rim(driver_rim_id)
    vbios_xml = fetch_rim(vbios_rim_id)
    driver_root = verify_xmldsig(driver_xml, "driver", args.rim_root)
    vbios_root = verify_xmldsig(vbios_xml, "vbios", args.rim_root)

    driver_g = parse_golden(driver_root, "driver")
    vbios_g = parse_golden(vbios_root, "vbios")
    print(f"driver golden: {len(driver_g)} ({sum(1 for m in driver_g.values() if m['active'])} active)")
    print(f"vbios  golden: {len(vbios_g)} ({sum(1 for m in vbios_g.values() if m['active'])} active)")

    golden = combine(driver_g, vbios_g)
    print(f"combined active golden: {len(golden)} indexes")

    # Compare (nvtrust Verifier.verify)
    mismatches = []
    for i in sorted(golden):
        if i == 35 and not is_msr35_valid:
            continue
        rt = runtime[i] if i < len(runtime) else None
        m = golden[i]
        ok = rt is not None and any(v == rt and m["size"] == len(rt) // 2 for v in m["values"])
        if not ok:
            mismatches.append((i, m["source"]))
    if mismatches:
        print(f"MISMATCH at {mismatches}")
        sys.exit(1)
    print(f"\n*** MATCH: all {len([i for i in golden if not (i==35 and not is_msr35_valid)])} active golden indexes match runtime. GPU in expected state. ***")

    # Emit Go golden table
    emit_go(driver_version, vbios_version, golden, args.out)


def emit_go(driver, vbios, golden, out_path):
    lines = []
    for i in sorted(golden):
        m = golden[i]
        vals = ", ".join(f'"{v}"' for v in m["values"])
        lines.append(f'\t{i}: {{Size: {m["size"]}, Source: "{m["source"]}", Values: []string{{{vals}}}}},')
    go = f'''// Code generated by rim_extract.py; DO NOT EDIT.
// Golden measurements for NVIDIA GH100 driver {driver} + VBIOS {vbios},
// extracted from NVIDIA-signed driver+VBIOS RIMs (XML-DSig verified against the
// pinned NVIDIA RIM root) and validated end-to-end against a real GPU report.
package main

var goldenGH100 = goldenTable{{
\tDriver: "{driver}",
\tVBIOS:  "{vbios}",
\tMeasurements: map[int]goldenMeasurement{{
{chr(10).join(lines)}
\t}},
}}
'''
    open(out_path, "w").write(go)
    print(f"wrote {out_path} ({len(golden)} measurements) -- run gofmt -w on it")


if __name__ == "__main__":
    main()
