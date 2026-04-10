# USSD Flow Exchange Server — Node.js

The **reference implementation** of the Monime USSD Flow Exchange Server with full **RSA-OAEP-SHA256 + AES-128-GCM** encryption support. Deployable to Vercel as a serverless function.

This is the same encryption logic used in Monime's production exchange servers. All other language implementations are tested against this reference.

## Encryption Protocol

| Step | Algorithm | Details |
|------|-----------|---------|
| Key delivery | RSA-OAEP | SHA-256 hash, SHA-256 MGF1, 2048-bit key |
| Payload encryption | AES-128-GCM | 12-byte IV, 16-byte auth tag |
| Wire format | Base64 | `[1 byte IV len][12 byte IV][ciphertext][16 byte tag]` |

> **Node.js note:** `oaepHash: "sha256"` in `crypto.privateDecrypt()` sets SHA-256 for **both** the OAEP hash and the MGF1 hash. This is the behavior all other languages must match.

## Prerequisites

- Node.js 18+
- An RSA-2048 key pair (see [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup))

## Local Development

```bash
# No dependencies to install — uses built-in crypto module

# Set your private key
export MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"

# Run with Vercel dev
npx vercel dev

# Test with a plain (unencrypted) request
curl -X POST http://localhost:3000/api/exchange \
  -H 'Content-Type: application/json' \
  -d '{
    "global": {"sessionId": "test-001", "networkName": "test", "subscriberId": "hash", "subscriberMsisdn": "+23200****00"},
    "currentPage": "security_test_start",
    "flowData": {}
  }'
```

## Deploy to Vercel

```bash
npm i -g vercel
vercel
vercel env add MONIME_RSA_PRIVATE_KEY
```

## Dependencies

**None** — uses only the Node.js built-in `crypto` module.

## Related

- [Encryption Model](https://docs.monime.io/guide/ussd-flows/security/overview)
- [Decrypting & Responding](https://docs.monime.io/guide/ussd-flows/security/implement)
- [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup)
