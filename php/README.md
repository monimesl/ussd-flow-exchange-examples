# USSD Flow Exchange Server — PHP

A PHP implementation of the Monime USSD Flow Exchange Server with full **RSA-OAEP-SHA256 + AES-128-GCM** encryption support. Deployable to Vercel with the community PHP runtime.

This server receives encrypted exchange requests from Monime, decrypts them, processes a test USSD flow, encrypts the response, and returns it.

## Encryption Protocol

| Step | Algorithm | Details |
|------|-----------|---------|
| Key delivery | RSA-OAEP | SHA-256 hash, SHA-256 MGF1 (**requires phpseclib**) |
| Payload encryption | AES-128-GCM | 12-byte IV, 16-byte auth tag |
| Wire format | Base64 | `[1 byte IV len][12 byte IV][ciphertext][16 byte tag]` |

> **Important:** PHP's native `openssl_private_decrypt()` with `OPENSSL_PKCS1_OAEP_PADDING` always uses **SHA-1** for the OAEP hash. Monime encrypts with **SHA-256**. This implementation uses [phpseclib v3](https://phpseclib.com/) for RSA decryption to ensure SHA-256 compatibility. The AES-GCM step uses PHP's native OpenSSL functions, which work correctly.

## Prerequisites

- PHP 8.1+
- Composer
- An RSA-2048 key pair (see [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup))

## Local Development

```bash
# Install dependencies
composer install

# Set your private key
export MONIME_RSA_PRIVATE_KEY="$(cat private_key.pem)"

# Run with PHP's built-in server
php -S localhost:3000

# Test with a plain (unencrypted) request
curl -X POST http://localhost:3000/api/exchange.php \
  -H 'Content-Type: application/json' \
  -d '{
    "global": {"sessionId": "test-001", "networkName": "test", "subscriberId": "hash", "subscriberMsisdn": "+23200****00"},
    "currentPage": "security_test_start",
    "flowData": {}
  }'
```

## Deploy to Vercel

```bash
# Install dependencies first
composer install

# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Set the environment variable in Vercel dashboard or CLI
vercel env add MONIME_RSA_PRIVATE_KEY
```

After deploying:
1. Copy your deployment URL (e.g., `https://ussd-flow-exchange-php.vercel.app`)
2. In the Monime dashboard, set the exchange URL to `https://your-url.vercel.app/api/exchange`
3. Upload the matching RSA public key in the flow's Security settings
4. Test the flow via USSD

## Health Check

```bash
curl https://your-url.vercel.app/api/exchange
# Returns: {"status": "ok", "language": "php", "key_loaded": true, ...}
```

## Dependencies

- [`phpseclib/phpseclib`](https://phpseclib.com/) v3 — RSA-OAEP-SHA256 decryption (PHP's native OpenSSL cannot use SHA-256 for OAEP)
- PHP OpenSSL extension — AES-128-GCM encryption/decryption (built-in, works correctly)

## Known Issue: PHP openssl_private_decrypt and OAEP

PHP's native `openssl_private_decrypt($data, $decrypted, $key, OPENSSL_PKCS1_OAEP_PADDING)` **always uses SHA-1** for the OAEP hash algorithm. There is no parameter to change it to SHA-256.

Monime encrypts the AES key with RSA-OAEP using **SHA-256** for both the hash and MGF1. Using `openssl_private_decrypt` will produce a decryption error because the hash algorithms don't match.

**The fix:** Use phpseclib v3 instead:

```php
use phpseclib3\Crypt\PublicKeyLoader;

$privateKey = PublicKeyLoader::load($pemString)
    ->withHash('sha256')
    ->withMGFHash('sha256');

$aesKey = $privateKey->decrypt($encryptedKey);
```

## Related

- [Encryption Model](https://docs.monime.io/guide/ussd-flows/security/overview) — How the protocol works
- [Decrypting & Responding](https://docs.monime.io/guide/ussd-flows/security/implement) — Code examples in 5 languages
- [Key Setup](https://docs.monime.io/guide/ussd-flows/security/key-setup) — Generate and manage RSA key pairs
