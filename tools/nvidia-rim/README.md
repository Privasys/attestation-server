# NVIDIA GPU golden-measurement extractor

`rim_extract.py` bakes the pinned Go golden-measurement table
(`src/golden_gh100.go`) that the attestation server compares runtime GPU
firmware/VBIOS measurements against.

## Why offline

NVIDIA publishes Reference Integrity Manifests (RIMs) as ISO-19770 SWID
documents signed with XML-DSig. Go has no safe XML-DSig verifier, so we do not
parse RIMs at request time. Instead this tool (running the same `signxml` /
`lxml` stack as NVIDIA's nvtrust) verifies each RIM's signature against the
pinned NVIDIA RIM root, applies nvtrust's combine rules (active driver
measurements plus active VBIOS measurements, no index conflict), validates the
result end to end against a real GPU report, and emits a Go table. The server
(`src/nvidia_rim.go`) re-derives runtime measurements from the *signed* SPDM
report and compares them, replicating nvtrust `Verifier.verify` exactly.

## Regenerating (new driver or VBIOS)

The table is pinned to one exact `(driver, VBIOS)` pair. When NVIDIA ships a new
GPU driver or VBIOS, capture a fresh attestation report from a genuine CC GPU on
that driver/VBIOS (the enclave `gpu-attest` daemon writes the evidence envelope;
its TLV `0x02` field is the raw report), then:

```
pip install signxml lxml
# verifier_RIM_root.pem ships with nvtrust under
#   guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/
python3 rim_extract.py \
    --report /path/to/gpu_atst_report.bin \
    --rim-root /path/to/verifier_RIM_root.pem \
    --out ../../src/golden_gh100.go
gofmt -w ../../src/golden_gh100.go
```

The tool fetches the matching driver and VBIOS RIMs from
`https://rim.attestation.nvidia.com`, prints the verification steps, and refuses
to emit a table unless every active golden index matches the captured report.
Add further `(driver, VBIOS)` tables to the `goldenTables` registry in
`src/nvidia_rim.go`.
