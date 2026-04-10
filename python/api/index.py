"""
Monime USSD Flow Exchange Server — Python (Flask)

Implements the full hybrid RSA-OAEP + AES-128-GCM encryption protocol
for receiving and responding to Monime USSD flow exchange requests.

Deploy to Vercel as a Python serverless function.
"""

import os
import json
import base64
from flask import Flask, request, jsonify, make_response

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


# ---------------------------------------------------------------------------
# 1. Load RSA private key once at cold-start
# ---------------------------------------------------------------------------
_raw_pem = os.environ.get("MONIME_RSA_PRIVATE_KEY", "")

# Normalize: strip surrounding quotes, replace literal \n with real newlines
_pem = _raw_pem.strip()
if _pem.startswith('"') and _pem.endswith('"'):
    _pem = _pem[1:-1]
_pem = _pem.replace("\\n", "\n")

private_key = None
if _pem:
    try:
        private_key = load_pem_private_key(_pem.encode(), password=None)
    except Exception as e:
        print(f"[Exchange] Failed to load private key: {e}")


# ---------------------------------------------------------------------------
# 2. Crypto helpers
# ---------------------------------------------------------------------------

def decrypt_aes_key(encrypted_key: bytes) -> bytes:
    """RSA-OAEP-SHA256 decrypt the one-time AES key."""
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_exchange_data(encrypted_data: bytes, aes_key: bytes) -> dict:
    """
    AES-128-GCM decrypt the exchange payload.

    Blob layout: [1 byte IV length][12 bytes IV][ciphertext][16 bytes GCM auth tag]
    Python's AESGCM handles the auth tag automatically when appended to ciphertext.
    """
    iv_length = encrypted_data[0]  # always 12
    iv = encrypted_data[1 : 1 + iv_length]
    ciphertext_with_tag = encrypted_data[1 + iv_length :]

    decrypted = AESGCM(aes_key).decrypt(iv, ciphertext_with_tag, None)
    return json.loads(decrypted.decode("utf-8"))


def encrypt_response(response_obj: dict, aes_key: bytes) -> str:
    """
    AES-128-GCM encrypt the response with a fresh IV.

    Returns base64-encoded blob: [1 byte IV length][12 bytes IV][ciphertext + 16 bytes auth tag]
    """
    iv = os.urandom(12)
    ciphertext_with_tag = AESGCM(aes_key).encrypt(
        iv,
        json.dumps(response_obj).encode("utf-8"),
        None,
    )

    # Build blob: [iv_length (1 byte)][iv][ciphertext + tag]
    blob = bytes([len(iv)]) + iv + ciphertext_with_tag
    return base64.b64encode(blob).decode("ascii")


def decrypt_request(body: dict) -> tuple:
    """
    Full request decryption pipeline.
    Returns (aes_key, exchange_request_dict).
    """
    encrypted_key = base64.b64decode(body["encryptedAesKey"])
    encrypted_data = base64.b64decode(body["encryptedExchangeData"])

    aes_key = decrypt_aes_key(encrypted_key)
    exchange_request = decrypt_exchange_data(encrypted_data, aes_key)

    return aes_key, exchange_request


# ---------------------------------------------------------------------------
# 3. Flow handler — mirrors the security-test flow
# ---------------------------------------------------------------------------

def handle_exchange(exchange_request: dict) -> dict:
    """Process the exchange request and return a response."""
    current_page = exchange_request.get("currentPage", "")

    if current_page == "security_test_start":
        return {
            "action": "navigate",
            "pageId": "security_test_menu",
            "pageData": {
                "items": [
                    {"label": "Continue", "value": "continue"},
                    {"label": "Cancel", "value": "cancel"},
                ],
                "message": "Security test flow (Python). Select an option.",
            },
        }

    if current_page == "security_test_menu":
        flow_data = exchange_request.get("flowData", {})
        value = str(flow_data.get("security_test_menu", "")).strip().lower()

        if value == "continue":
            return {
                "action": "navigate",
                "pageId": "security_test_result",
                "pageData": {
                    "message": "You chose Continue. Security test completed successfully.",
                },
            }

        if value == "cancel":
            return {
                "action": "stop",
                "message": "Security test cancelled.",
            }

        return {
            "action": "stop",
            "message": "Invalid option. Please try again.",
        }

    if current_page == "security_test_result":
        return {
            "action": "stop",
            "message": "Thank you for using the security test flow (Python).",
        }

    return {
        "action": "stop",
        "message": f"Unknown page: {current_page}",
    }


# ---------------------------------------------------------------------------
# 4. Routes
# ---------------------------------------------------------------------------

@app.route("/api/exchange", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "language": "python",
        "service": "ussd-flow-exchange",
        "encryption": "RSA-OAEP-SHA256 + AES-128-GCM",
        "key_loaded": private_key is not None,
    })


@app.route("/api/exchange", methods=["POST"])
def exchange():
    """Main exchange endpoint."""
    try:
        body = request.get_json(force=True)
        if body is None:
            return jsonify({"action": "stop", "message": "Invalid JSON"}), 400

        # Check if request is encrypted
        is_encrypted = (
            isinstance(body, dict)
            and "encryptedAesKey" in body
            and "encryptedExchangeData" in body
            and isinstance(body.get("encryptedAesKey"), str)
            and isinstance(body.get("encryptedExchangeData"), str)
        )

        aes_key = None
        exchange_request = None

        if is_encrypted and private_key:
            # Encrypted request path
            try:
                aes_key, exchange_request = decrypt_request(body)
                session_id = exchange_request.get("global", {}).get("sessionId", "N/A")
                page = exchange_request.get("currentPage", "N/A")
                print(f"[Exchange] Decryption OK — session: {session_id}, page: {page}")
            except Exception as e:
                print(f"[Exchange] Decryption FAILED: {e}")
                return jsonify({"action": "stop", "message": "Decryption failed"}), 400

        elif (
            isinstance(body, dict)
            and "currentPage" in body
            and "global" in body
        ):
            # Plain-text request path
            exchange_request = body
            page = exchange_request.get("currentPage", "N/A")
            print(f"[Exchange] Plain request — page: {page}")

        else:
            return jsonify({"action": "stop", "message": "Invalid request body"}), 400

        # Process the exchange
        response = handle_exchange(exchange_request)

        # Send response
        if aes_key:
            # Encrypt the response
            encrypted = encrypt_response(response, aes_key)
            resp = make_response(encrypted, 200)
            resp.headers["Content-Type"] = "text/plain"
            return resp
        else:
            return jsonify(response)

    except Exception as e:
        print(f"[Exchange] Unhandled error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"action": "stop", "message": "Internal server error"}), 500
