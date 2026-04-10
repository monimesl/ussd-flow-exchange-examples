# USSD Flow Exchange Server — Java

A Java implementation of the Monime USSD Flow Exchange Server with full **RSA-OAEP-SHA256 + AES-128-GCM** encryption support. Packaged as a Docker container for deployment.

This server receives encrypted exchange requests from Monime, decrypts them, processes a test USSD flow, encrypts the response, and returns it.

## Encryption Protocol

| Step | Algorithm | Details |
|------|-----------|---------|
| Key delivery | RSA-OAEP | SHA-256 hash, **SHA-256 MGF1** (explicit), 2048-bit key |
| Payload encryption | AES-128-GCM | 12-byte IV, 16-byte auth tag |
| Wire format | Base64 | `[1 byte IV len][12 byte IV][ciphertext][16 byte tag]` |

> **Important:** Java's `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` defaults to **SHA-1 for MGF1**, which does NOT match Monime's SHA-256. This implementation explicitly sets `MGF1ParameterSpec.SHA256` via `OAEPParameterSpec` to ensure compatibility.

## Prerequisites

- Java 17+ (JDK)
- Docker (for containerized deployment)
- An RSA-2048 key pair (see [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup))

## Local Development

```bash
# Compile
mkdir -p out
javac -d out $(find src -name "*.java")

# Set your private key
export MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"

# Run
java -cp out io.monime.exchange.ExchangeHandler

# Test with a plain (unencrypted) request
curl -X POST http://localhost:3000/api/exchange \
  -H 'Content-Type: application/json' \
  -d '{
    "global": {"sessionId": "test-001", "networkName": "test", "subscriberId": "hash", "subscriberMsisdn": "+23200****00"},
    "currentPage": "security_test_start",
    "flowData": {}
  }'
```

## Deploy with Docker

```bash
# Build
docker build -t ussd-flow-exchange-java .

# Run
docker run -p 3000:3000 \
  -e MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)" \
  ussd-flow-exchange-java
```

## Deploy to Railway / Render / Fly.io

Java is not natively supported by Vercel. Use one of these alternatives:

### Railway
```bash
# Install Railway CLI and deploy
railway init
railway up
railway variables set MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"
```

### Fly.io
```bash
fly launch
fly secrets set MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"
fly deploy
```

After deploying:
1. Copy your deployment URL
2. In the Monime dashboard, set the exchange URL to `https://your-url/api/exchange`
3. Upload the matching RSA public key in the flow's Security settings
4. Test the flow via USSD

## Health Check

```bash
curl https://your-url/api/exchange
# Returns: {"status": "ok", "language": "java", "key_loaded": true, ...}
```

## Dependencies

**None** — uses only the Java standard library:
- `javax.crypto.Cipher` — RSA-OAEP and AES-GCM
- `javax.crypto.spec.OAEPParameterSpec` — Explicit SHA-256 for both OAEP hash and MGF1
- `javax.crypto.spec.GCMParameterSpec` — AES-GCM parameters
- `java.security.KeyFactory` — RSA key loading
- `com.sun.net.httpserver.HttpServer` — Built-in HTTP server

## Known Issue: Java OAEP MGF1 Default

Java's `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` uses SHA-256 for the OAEP hash but **SHA-1 for MGF1** by default. Monime uses SHA-256 for both. You MUST use `OAEPParameterSpec` to explicitly set the MGF1 hash:

```java
OAEPParameterSpec oaepParams = new OAEPParameterSpec(
    "SHA-256",                        // OAEP hash
    "MGF1",                           // Mask generation function
    MGF1ParameterSpec.SHA256,          // MGF1 hash — MUST be SHA-256
    PSource.PSpecified.DEFAULT
);
cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
```

## Related

- [Encryption Model](https://docs.monime.io/guide/ussd-flows/security/overview) — How the protocol works
- [Decrypting & Responding](https://docs.monime.io/guide/ussd-flows/security/implement) — Code examples in 5 languages
- [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup) — Generate and manage RSA key pairs
