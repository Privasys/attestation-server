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
| `--oidc-issuer`      | `OIDC_ISSUER`      | —                                         | OIDC issuer URL (**required**)    |
| `--oidc-audience`    | `OIDC_AUDIENCE`    | `attestation-server`                      | Expected `aud` claim              |
| `--oidc-client-role` | `OIDC_CLIENT_ROLE`  | `attestation-server:client`              | Required OIDC role                |
| `--oidc-role-claim`  | `OIDC_ROLE_CLAIM`   | `urn:zitadel:iam:org:project:roles`     | JWT claim key containing roles    |
| `--listen`           | `LISTEN_ADDR`      | `:8080`                                   | Listen address                    |

### Role claim formats

The server checks three claim paths (matching Zitadel, Keycloak, and
standard OIDC providers):

1. **Zitadel** — `urn:zitadel:iam:org:project:roles` (map of role → metadata)
2. **Standard** — `roles` (string array)
3. **Keycloak** — `realm_access.roles` (string array)

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
(e.g. Zitadel, Keycloak, Auth0).

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
  "message": "TDX quote verified (signature + certificate chain)"
}
```

The server auto-detects the quote type (TDX v4 or SGX v3) from the version
field and routes to the appropriate verifier.

## Installation guides

Step-by-step deployment guides for specific cloud providers:

- [Google Cloud](install/Google%20Cloud.md)
- [OVH Cloud](install/OVH%20Cloud.md)

## Third-party dependencies

| Library | License | Usage |
|---------|---------|-------|
| [google/go-tdx-guest](https://github.com/google/go-tdx-guest) | Apache 2.0 | TDX quote parsing and signature verification |

Full license texts are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).