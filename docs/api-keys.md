# API Key Management

The Attestation Server uses **Ed25519 JWT tokens** for authentication.
Every request must include an `Authorization: Bearer <token>` header.

## Scopes

| Scope    | Description                                |
|----------|--------------------------------------------|
| `verify` | Submit quotes to `POST /api/verify`        |
| `admin`  | Issue new API keys via `POST /api/issue`   |

A token can hold multiple scopes, comma-separated (e.g. `"verify,admin"`).

---

## 1. Generate the Ed25519 signing key pair (one-time)

```bash
openssl genpkey -algorithm Ed25519 -out server-jwt.key
openssl pkey    -in server-jwt.key -pubout -out server-jwt.pub
chmod 600 server-jwt.key
```

Keep **`server-jwt.key`** secret on the server.
Distribute `server-jwt.pub` only if external services need to verify tokens independently.

## 2. Issue tokens via CLI

The server binary doubles as a CLI tool — no running server required.

```bash
# Standard user token (verify-only, 90 days)
JWT_SIGNING_KEY_FILE=server-jwt.key ./dist/attestation-server issue \
  --subject "acme-corp" --scope "verify" --days 90

# Admin token (can issue + verify, 365 days)
JWT_SIGNING_KEY_FILE=server-jwt.key ./dist/attestation-server issue \
  --subject "bertrand" --scope "verify,admin" --days 365
```

Output:
```
Subject : acme-corp
Scope   : verify
Expires : 2025-06-01T12:00:00Z
Token   :
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

Give the token string to the user.

### CLI flags

| Flag        | Default   | Description                       |
|-------------|-----------|-----------------------------------|
| `--subject` | `"user"`  | Token holder identifier           |
| `--scope`   | `"verify"`| Comma-separated list of scopes    |
| `--days`    | `30`      | Token validity in days            |

## 3. Issue tokens via HTTP

Requires a running server and an **admin-scoped** token.

```bash
curl -X POST https://gcp-lon-1.dcap.privasys.org/api/issue \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "bob", "scope": "verify", "days_valid": 30}'
```

Response:
```json
{
  "token":   "eyJhbGciOi...",
  "subject": "bob",
  "scope":   "verify",
  "expires": "2025-04-01T00:00:00Z"
}
```

### Request body

| Field        | Type   | Required | Default    | Description              |
|--------------|--------|----------|------------|--------------------------|
| `subject`    | string | yes      | —          | Token holder identifier  |
| `scope`      | string | no       | `"verify"` | Comma-separated scopes   |
| `days_valid` | int    | no       | `30`       | Token validity in days   |

## 4. Using the token

Pass it in the `Authorization` header of every request:

```
Authorization: Bearer eyJhbGciOiJFZERTQSIs...
```

All ra-tls-clients accept a `--dcap-key` flag (or `DCAP_KEY` environment variable)
that sets this header automatically.
