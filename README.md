# Privasys Attestation Server

A lightweight Go server that verifies hardware attestation quotes from
Confidential Computing platforms (Intel TDX, SGX — more vendors coming),
secured with Ed25519 JWT authentication.

## Endpoints

| Method | Path            | Scope    | Description                          |
|--------|-----------------|----------|--------------------------------------|
| POST   | `/api/verify`   | verify   | Verify a hardware attestation quote  |
| POST   | `/api/issue`    | admin    | Issue a new API key (JWT)            |

## Project structure

```
src/
  main.go       Entry point, configuration, HTTP server
  verify.go     Quote verification (TDX via go-tdx-guest, SGX via external tool)
  auth.go       JWT validation and Bearer-token middleware
  apikeys.go    API key issuance (HTTP endpoint + CLI)
docs/
  api-keys.md   API key generation and management guide
install/
  Google Cloud.md   Installation guide for GCP
  OVH Cloud.md      Installation guide for OVH Cloud
dist/           Build output (git-ignored)
```

---

## Build

```bash
go build -o dist/attestation-server ./src/
```

## Generate the Ed25519 signing key (one-time)

```bash
openssl genpkey -algorithm Ed25519 -out server-jwt.key
openssl pkey -in server-jwt.key -pubout -out server-jwt.pub
chmod 600 server-jwt.key
```

Keep `server-jwt.key` secret on the server.
You only need `server-jwt.pub` if external services verify tokens independently.

## systemd service

Create `/etc/systemd/system/attestation-server.service`:

```ini
[Unit]
Description=Privasys Attestation Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/attestation-server
Environment=JWT_SIGNING_KEY_FILE=/opt/attestation-server/server-jwt.key
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

## API key management

See [docs/api-keys.md](docs/api-keys.md) for the full guide on generating,
issuing, and using JWT API keys.

Quick start — issue a verify-only token via CLI (no running server needed):

```bash
JWT_SIGNING_KEY_FILE=server-jwt.key ./dist/attestation-server issue \
  --subject "acme-corp" --scope "verify" --days 90
```

## Verify a quote

```bash
curl -X POST https://gcp-lon-1.dcap.privasys.org/api/verify \
  -H "Authorization: Bearer <TOKEN>" \
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
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) | MIT | JWT token signing and validation |

Full license texts are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).