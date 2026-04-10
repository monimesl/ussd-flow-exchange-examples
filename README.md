# USSD Flow Exchange Examples

Reference implementations of the Monime USSD Flow Exchange Server in multiple languages. Each implementation handles the full **RSA-OAEP-SHA256 + AES-128-GCM** hybrid encryption protocol for receiving and responding to encrypted exchange requests.

These are working, tested, deployable servers — not just code snippets. Use them to verify your encryption implementation works, or as a starting point for building your own exchange server.

## Implementations

| Language | Directory | Framework | Deployment | Dependencies |
|----------|-----------|-----------|------------|--------------|
| [Node.js](./nodejs) | `nodejs/` | Built-in crypto | Vercel | None (reference implementation) |
| [Python](./python) | `python/` | Flask | Vercel | `cryptography` |
| [Go](./go) | `go/` | net/http | Vercel | None (stdlib) |
| [Java](./java) | `java/` | JDK HttpServer | Docker (Railway/Render) | None (JDK) |
| [PHP](./php) | `php/` | Plain PHP | Vercel (community runtime) | `phpseclib/phpseclib` v3 |

## Security Test Flow

The [`flow/`](./flow) directory contains the USSD flow JSON definition used for testing. Import it into the Monime dashboard and point its URLs to your deployed exchange server. See [`flow/README.md`](./flow/README.md) for setup instructions.

## Encryption Protocol

All implementations follow the same protocol:

```
Request (Monime → Your Server):
  1. Monime generates a one-time AES-128 key
  2. Encrypts the payload with AES-128-GCM (12-byte IV, 16-byte auth tag)
  3. Wraps the AES key with your RSA public key (OAEP, SHA-256 hash, SHA-256 MGF1)
  4. Sends POST { encryptedAesKey, encryptedExchangeData }

Response (Your Server → Monime):
  1. AES-128-GCM encrypt with the SAME AES key + FRESH 12-byte IV
  2. Return raw base64 blob as text/plain
```

## Quick Start

```bash
# Clone this repo
git clone https://github.com/monimesl/ussd-flow-exchange-examples
cd ussd-flow-exchange-examples

# Pick a language
cd python  # or go, java, php

# Generate a key pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Set the private key
export MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"

# See each language's README for specific run instructions
```

## Language-Specific Notes

### Java: MGF1 defaults to SHA-1
Java's `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` uses SHA-1 for MGF1 by default. This implementation explicitly sets `MGF1ParameterSpec.SHA256` via `OAEPParameterSpec`.

### PHP: openssl_private_decrypt only supports SHA-1 OAEP
PHP's native `openssl_private_decrypt()` hardcodes SHA-1 for OAEP. This implementation uses `phpseclib v3` with `->withHash('sha256')->withMGFHash('sha256')`.

## Adding a New Language

To add a new language implementation:

1. Create a new directory (e.g., `ruby/`, `csharp/`)
2. Implement the full encrypt/decrypt protocol (see any existing implementation as reference)
3. Include: `README.md`, deployment config, `.env.example`
4. Ensure it handles both encrypted and plain-text requests
5. Include a GET health check endpoint
6. Submit a pull request

## Documentation

- [Encryption Model](https://docs.monime.io/guide/ussd-flows/security/overview)
- [Decrypting & Responding](https://docs.monime.io/guide/ussd-flows/security/implement)
- [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup)
- [Testing](https://docs.monime.io/guide/ussd-flows/security/testing)

## License

MIT
