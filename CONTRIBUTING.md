# Contributing to Attestation Server

Thank you for your interest in contributing! This project is a lightweight Go server that verifies hardware attestation quotes (Intel TDX, SGX, and more in the future), secured with Ed25519 JWT authentication.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Ensure you have Go 1.22+ installed.
3. Build:
   ```bash
   go build -o dist/attestation-server ./src/
   ```

## Project Structure

| Path | Description |
|------|-------------|
| `src/main.go` | Entry point, configuration, HTTP server |
| `src/verify.go` | Quote verification (TDX via go-tdx-guest, SGX via external tool) |
| `src/auth.go` | JWT validation and Bearer-token middleware |
| `src/apikeys.go` | API key issuance (HTTP endpoint + CLI) |
| `docs/api-keys.md` | API key generation and management guide |

## Making Changes

- Follow the existing code style — use `gofmt` and keep imports organised.
- Keep commits focused: one logical change per commit.
- Write meaningful commit messages (e.g. `verify: add AMD SEV-SNP backend`).
- If adding a new attestation backend, add the verifier function in `src/verify.go` and wire it into the `quoteType` switch.

## Submitting a Pull Request

1. Create a feature branch from `main`:
   ```bash
   git checkout -b my-feature
   ```
2. Make your changes and commit.
3. Push to your fork and open a Pull Request against `main`.
4. Describe what you changed and why.

## Reporting Issues

If you find a bug or have a suggestion, please [open an issue](https://github.com/Privasys/attestation-server/issues). Include:

- A clear description of the problem or suggestion.
- Steps to reproduce (for bugs).
- The TEE platform you are testing against.

## Licence and Contributor Licence Agreement

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Before we can merge your first pull request, you need to accept the
[Privasys Contributor Licence Agreement](https://github.com/Privasys/cla). You
keep the copyright in your work; the agreement lets Privasys also license it
under other terms, and Privasys commits to keeping it available under an
open-source licence. A check on your pull request explains how to accept: one
comment, once, for every Privasys repository. If you contribute as part of your
work for an employer, your employer may need to sign the entity agreement
instead.
