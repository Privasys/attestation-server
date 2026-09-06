# Privasys Attestation Server

A lightweight Go server that verifies hardware attestation quotes from
Confidential Computing platforms (Intel TDX, SGX — more vendors coming),
secured with OIDC bearer token authentication.

## Endpoint

| Method | Path | Role                         | Description                         |
|--------|------|------------------------------|-------------------------------------|
| POST   | `/`  | `attestation-server:client`  | Verify a hardware attestation quote |

## Project structure

```
src/
  main.go       Entry point, configuration, HTTP server
  verify.go     Quote verification (TDX via go-tdx-guest, SGX pure-Go DCAP v3)
  auth.go       OIDC JWKS verification and Bearer-token middleware
  sgx.go        Pure-Go SGX DCAP v3 quote parser and verifier
docs/
  authentication.md   OIDC authentication guide
install/
  Google Cloud.md     Installation guide for GCP
  OVH Cloud.md        Installation guide for OVH Cloud
dist/                 Build output (git-ignored)
```

---

## Build

```bash
go build -o dist/attestation-server ./src/
```

## Configuration

The server requires an OIDC provider for bearer token authentication.
All flags also accept environment variable overrides.

| Flag                 | Env var            | Default                                   | Description                       |
|----------------------|--------------------|-------------------------------------------|-----------------------------------|
| `--oidc-issuer`      | `OIDC_ISSUER`      | —                                         | OIDC issuer URL(s) (**required**, comma-separated for multiple) |
| `--oidc-audience`    | `OIDC_AUDIENCE`    | `attestation-server`                      | Expected `aud` claim              |
| `--oidc-client-role` | `OIDC_CLIENT_ROLE`  | `attestation-server:client`              | Required OIDC role                |
| `--oidc-role-claim`  | `OIDC_ROLE_CLAIM`   | `roles`                                  | JWT claim key containing roles    |
| `--listen`           | `LISTEN_ADDR`      | `:8080`                                   | Listen address                    |

### Multi-issuer support

The server supports multiple OIDC issuers. Provide a comma-separated list:

```bash
OIDC_ISSUER=https://auth.example.com,https://broker.example.com
```

Each issuer gets its own JWKS cache and OIDC discovery. On token validation,
the server reads the `iss` claim from the JWT and validates against the
corresponding issuer's JWKS. This allows accepting tokens from both an
identity provider (e.g. Privasys ID) and an app attestation broker.

### Role claim formats

The server checks two claim paths (matching standard OIDC and Keycloak):

1. **Standard** (default) — `roles` (RFC 9068 §2.2.3.1 flat string array)
2. **Keycloak** — `realm_access.roles` (string array)

## systemd service

Create `/etc/systemd/system/attestation-server.service`:

```ini
[Unit]
Description=Privasys Attestation Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/attestation-server
Environment=OIDC_ISSUER=https://auth.example.com
ExecStart=/opt/attestation-server/attestation-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then activate it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now attestation-server
sudo systemctl status attestation-server
```

View logs:

```bash
journalctl -u attestation-server -f
```

## Authentication

See [docs/authentication.md](docs/authentication.md) for the full OIDC setup guide.

Callers must present a valid OIDC bearer token with the
`attestation-server:client` role. Tokens are issued by your OIDC provider
(e.g. Privasys ID, Keycloak, Auth0).

## Verify a quote

```bash
curl -X POST https://as.privasys.org/ \
  -H "Authorization: Bearer <OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"quote": "<base64-encoded-quote>"}'
```

Response:

```json
{
  "success": true,
  "status": "OK",
  "mrtd": "feb74866...",
  "rtmrs": ["...", "...", "...", "..."],
  "platform": {
    "ppid": "414afbe506e8ac361add41f3133aab6f",
    "platformInstanceId": "c055fc7b49bd4185dda796bf1795af32",
    "fmspc": "00806f050000"
  },
  "pckRevocationChecked": true,
  "message": "TDX quote verified (signature + certificate chain)"
}
```

The server auto-detects the quote type (TDX v4, SGX v3, or SEV-SNP) from
the version field and routes to the appropriate verifier. Successful TDX
verifications include the MRTD and the four RTMRs (hex).

### Revocation

The PCK certificate chain of every SGX and TDX quote is checked against Intel's
current CRLs: the PCK CRL of the issuing CA (Processor or Platform) for the
leaf, and the Root CA CRL for the issuing CA itself. A revoked certificate, or
a CRL that cannot be obtained or has expired, fails the verification
(`PCK_REVOCATION_MODE=enforce`, the default); `report` only records the
outcome in `pckRevocationChecked` and logs it; `off` skips the check. CRLs are
served through the same caching PCS getter as the TCB collateral, with the
24-hour grace window (`SGX_TCB_GRACE_HOURS`) through a PCS outage. This check
is independent of the TCB-status policy (`SGX_TCB_MODE`).

### Platform allow-list

A quote that verifies proves that a genuine TEE with the reported measurements
signed it, not which machine it came from. The `platform` object reports the
hardware identity read from the verified evidence: for Intel SGX and TDX the
PCK certificate's PPID and, on certificates issued by the PCK Platform CA, its
Platform Instance ID (SGX extension `1.2.840.113741.1.13.1.6`); for AMD
SEV-SNP the report's `chipId`. A relying party that knows which machines it
operates sends an allow-list with the request:

```json
{"quote": "<base64 quote>", "allowedPlatformIds": ["c055fc7b49bd4185dda796bf1795af32"]}
```

Entries are hex (case and separators ignored) and are matched against the
Platform Instance ID when present, else the PPID, else the CHIP_ID. Evidence
from any other platform fails with `"status": "PLATFORM_NOT_ALLOWED"`; so does
evidence whose platform identity cannot be read when a list is given. The
`ra-tls-clients` SDKs send the list from `VerificationPolicy.AllowedPlatformIDs`
and check the reported identity themselves as well.

### Event-log cross-check (TDX)

A TDX quote proves the final RTMR values but not how they were produced.
Supplying the CC event log lets the server bind the two: it parses the
log (TCG crypto-agile format, as read from
`/sys/firmware/acpi/tables/data/CCEL`), replays every extend
(`RTMR <- SHA384(RTMR || digest)`), and requires the reconstructed
registers to equal the quote's RTMRs. Any mismatch fails the
verification (fail closed), with the offending register and both values
in the error.

```bash
curl -X POST https://as.privasys.org/ \
  -H "Authorization: Bearer <OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "quote": "<base64 quote>",
    "eventLog": "<base64 CCEL>",
    "includeEventLog": true
  }'
```

On success the response carries `"eventLogVerified": true` and, when
`includeEventLog` is set, an `eventLog` array of decoded events
(`rtmr`, `eventType`, `digest`, and printable payloads such as
`grub_cmd` lines and the kernel command line). A verified log turns the
per-event digests into trustworthy fine-grained evidence: combined with
the per-release `measurements.json` published by
[cvm-images](https://github.com/Privasys/cvm-images), a verifier can
pinpoint exactly which boot component (shim, GRUB command, kernel,
cmdline) changed between two attestations instead of comparing opaque
register values.

## Installation guides

Step-by-step deployment guides for specific cloud providers:

- [Google Cloud](install/Google%20Cloud.md)
- [OVH Cloud](install/OVH%20Cloud.md)

## Third-party dependencies

| Library | License | Usage |
|---------|---------|-------|
| [google/go-tdx-guest](https://github.com/google/go-tdx-guest) | Apache 2.0 | TDX quote parsing and signature verification |

Full license texts are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).