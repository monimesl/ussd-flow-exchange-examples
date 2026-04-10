/**
 * Monime USSD Flow Exchange Server — Node.js
 *
 * Implements the full hybrid RSA-OAEP + AES-128-GCM encryption protocol
 * for receiving and responding to Monime USSD flow exchange requests.
 *
 * Deploy to Vercel as a Node.js serverless function.
 * Zero external dependencies — uses only the built-in crypto module.
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// 1. Load RSA private key once at cold-start
// ---------------------------------------------------------------------------

let privateKey = null;

function loadPrivateKey() {
  if (privateKey) return privateKey;

  let rawPem = process.env.MONIME_RSA_PRIVATE_KEY || "";

  // Normalize: strip surrounding quotes, replace literal \n
  let pem = rawPem.trim();
  if (pem.startsWith('"') && pem.endsWith('"')) {
    pem = pem.slice(1, -1);
  }
  pem = pem.replace(/\\n/g, "\n");

  if (!pem) {
    console.log("[Exchange] MONIME_RSA_PRIVATE_KEY not set");
    return null;
  }

  try {
    privateKey = crypto.createPrivateKey(pem);
    console.log("[Exchange] Private key loaded successfully");
    return privateKey;
  } catch (e) {
    console.error("[Exchange] Failed to load private key:", e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// 2. Crypto helpers
// ---------------------------------------------------------------------------

/**
 * RSA-OAEP-SHA256 decrypt the one-time AES key.
 *
 * oaepHash: "sha256" sets SHA-256 for BOTH the OAEP hash AND the MGF1 hash.
 * This is the reference implementation that all other languages must match.
 */
function decryptAesKey(encryptedKeyBuf) {
  return crypto.privateDecrypt(
    {
      key: loadPrivateKey(),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKeyBuf,
  );
}

/**
 * AES-128-GCM decrypt the exchange payload.
 *
 * Blob layout: [1 byte IV length][12 bytes IV][ciphertext][16 bytes GCM auth tag]
 * Node.js requires splitting the auth tag off manually.
 */
function decryptPayload(encryptedDataBuf, aesKey) {
  const ivLength = encryptedDataBuf[0]; // 12
  const iv = encryptedDataBuf.subarray(1, 1 + ivLength);
  const tag = encryptedDataBuf.subarray(encryptedDataBuf.length - 16);
  const ciphertext = encryptedDataBuf.subarray(
    1 + ivLength,
    encryptedDataBuf.length - 16,
  );

  const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv, {
    authTagLength: 16,
  });
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString("utf8"));
}

/**
 * AES-128-GCM encrypt the response with a fresh IV.
 *
 * Returns base64-encoded blob: [1 byte IV length][12 bytes IV][ciphertext][16 bytes auth tag]
 */
function encryptResponse(responseObject, aesKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, iv, {
    authTagLength: 16,
  });

  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(responseObject), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const blob = Buffer.alloc(1 + iv.length + ciphertext.length + tag.length);
  blob.writeUInt8(iv.length, 0);
  iv.copy(blob, 1);
  ciphertext.copy(blob, 1 + iv.length);
  tag.copy(blob, 1 + iv.length + ciphertext.length);

  return blob.toString("base64");
}

/**
 * Full request decryption pipeline.
 */
function decryptRequest(body) {
  const encryptedKeyBuf = Buffer.from(body.encryptedAesKey, "base64");
  const encryptedDataBuf = Buffer.from(body.encryptedExchangeData, "base64");

  const aesKey = decryptAesKey(encryptedKeyBuf);
  const exchangeRequest = decryptPayload(encryptedDataBuf, aesKey);

  return { aesKey, exchangeRequest };
}

// ---------------------------------------------------------------------------
// 3. Flow handler — mirrors the security-test flow
// ---------------------------------------------------------------------------

function handleExchange(exchangeRequest) {
  const { currentPage } = exchangeRequest;

  switch (currentPage) {
    case "security_test_start":
      return {
        action: "navigate",
        pageId: "security_test_menu",
        pageData: {
          items: [
            { label: "Continue", value: "continue" },
            { label: "Cancel", value: "cancel" },
          ],
          message: "Security test flow (Node.js). Select an option.",
        },
      };

    case "security_test_menu": {
      const flowData = exchangeRequest.flowData || {};
      const value = String(flowData.security_test_menu || "")
        .trim()
        .toLowerCase();

      if (value === "continue") {
        return {
          action: "navigate",
          pageId: "security_test_result",
          pageData: {
            message:
              "You chose Continue. Security test completed successfully.",
          },
        };
      }
      if (value === "cancel") {
        return { action: "stop", message: "Security test cancelled." };
      }
      return { action: "stop", message: "Invalid option. Please try again." };
    }

    case "security_test_result":
      return {
        action: "stop",
        message: "Thank you for using the security test flow (Node.js).",
      };

    default:
      return { action: "stop", message: `Unknown page: ${currentPage}` };
  }
}

// ---------------------------------------------------------------------------
// 4. Vercel serverless handler
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  // Health check
  if (req.method === "GET") {
    return res.json({
      status: "ok",
      language: "nodejs",
      service: "ussd-flow-exchange",
      encryption: "RSA-OAEP-SHA256 + AES-128-GCM",
      key_loaded: loadPrivateKey() !== null,
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({ action: "stop", message: "Method not allowed" });
  }

  try {
    const body = req.body;

    // Check if request is encrypted
    const isEncrypted =
      body &&
      typeof body.encryptedAesKey === "string" &&
      typeof body.encryptedExchangeData === "string";

    let aesKey = null;
    let exchangeRequest = null;

    if (isEncrypted && loadPrivateKey()) {
      try {
        const result = decryptRequest(body);
        aesKey = result.aesKey;
        exchangeRequest = result.exchangeRequest;
        console.log(
          `[Exchange] Decryption OK — session: ${exchangeRequest.global?.sessionId}, page: ${exchangeRequest.currentPage}`,
        );
      } catch (e) {
        console.error("[Exchange] Decryption FAILED:", e.message);
        return res
          .status(400)
          .json({ action: "stop", message: "Decryption failed" });
      }
    } else if (body && body.currentPage && body.global) {
      exchangeRequest = body;
      console.log(
        `[Exchange] Plain request — page: ${exchangeRequest.currentPage}`,
      );
    } else {
      return res
        .status(400)
        .json({ action: "stop", message: "Invalid request body" });
    }

    // Process the exchange
    const response = handleExchange(exchangeRequest);

    // Send response
    if (aesKey) {
      const encrypted = encryptResponse(response, aesKey);
      res.setHeader("Content-Type", "text/plain");
      return res.send(encrypted);
    } else {
      return res.json(response);
    }
  } catch (e) {
    console.error("[Exchange] Unhandled error:", e.message);
    return res
      .status(500)
      .json({ action: "stop", message: "Internal server error" });
  }
};
