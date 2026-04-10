# USSD Flow Exchange Server — Python

A Python implementation of the Monime USSD Flow Exchange Server with full **RSA-OAEP-SHA256 + AES-128-GCM** encryption support. Deployable to Vercel as a serverless function.

This server receives encrypted exchange requests from Monime, decrypts them, processes a test USSD flow, encrypts the response, and returns it.

## Encryption Protocol

| Step | Algorithm | Details |
|------|-----------|---------|
| Key delivery | RSA-OAEP | SHA-256 hash, SHA-256 MGF1, 2048-bit key |
| Payload encryption | AES-128-GCM | 12-byte IV, 16-byte auth tag |
| Wire format | Base64 | `[1 byte IV len][12 byte IV][ciphertext][16 byte tag]` |

## Prerequisites

- Python 3.9+
- An RSA-2048 key pair (see [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup))

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set your private key
export MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"

# Run the server (using a simple HTTP server wrapper)
python -c "
from http.server import HTTPServer
from api.exchange import handler
HTTPServer(('', 3000), handler).serve_forever()
" &

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
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Set the environment variable in Vercel dashboard or CLI
vercel env add MONIME_RSA_PRIVATE_KEY
```

After deploying:
1. Copy your deployment URL (e.g., `https://ussd-flow-exchange-python.vercel.app`)
2. In the Monime dashboard, set the exchange URL to `https://your-url.vercel.app/api/exchange`
3. Upload the matching RSA public key in the flow's Security settings
4. Test the flow via USSD

## Health Check

```bash
curl https://your-url.vercel.app/api/exchange
# Returns: {"status": "ok", "language": "python", "key_loaded": true, ...}
```

## Dependencies

- [`cryptography`](https://cryptography.io/) — RSA-OAEP-SHA256 decryption and AES-128-GCM encryption/decryption

## Related

- [Encryption Model](https://docs.monime.io/guide/ussd-flows/security/overview) — How the protocol works
- [Decrypting & Responding](https://docs.monime.io/guide/ussd-flows/security/implement) — Code examples in 5 languages
- [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup) — Generate and manage RSA key pairs
