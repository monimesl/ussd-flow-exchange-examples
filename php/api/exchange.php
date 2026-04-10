<?php
/**
 * Monime USSD Flow Exchange Server — PHP
 *
 * Implements the full hybrid RSA-OAEP + AES-128-GCM encryption protocol
 * for receiving and responding to Monime USSD flow exchange requests.
 *
 * IMPORTANT: Uses phpseclib v3 for RSA OAEP-SHA256 decryption because
 * PHP's native openssl_private_decrypt() with OPENSSL_PKCS1_OAEP_PADDING
 * always uses SHA-1 for the OAEP hash, which does NOT match Monime's SHA-256.
 *
 * Deploy to Vercel with the vercel-php community runtime.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

// ---------------------------------------------------------------------------
// 1. Load RSA private key once
// ---------------------------------------------------------------------------

$rawPem = getenv('MONIME_RSA_PRIVATE_KEY') ?: '';

// Normalize: strip surrounding quotes, replace literal \n
$pemStr = trim($rawPem);
if (str_starts_with($pemStr, '"') && str_ends_with($pemStr, '"')) {
    $pemStr = substr($pemStr, 1, -1);
}
$pemStr = str_replace('\\n', "\n", $pemStr);

$privateKey = null;
if ($pemStr) {
    try {
        $privateKey = PublicKeyLoader::load($pemStr);
        // Configure for OAEP with SHA-256 for both hash and MGF1
        $privateKey = $privateKey
            ->withHash('sha256')
            ->withMGFHash('sha256');
        error_log('[Exchange] Private key loaded successfully');
    } catch (\Exception $e) {
        error_log('[Exchange] Failed to load private key: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// 2. Crypto helpers
// ---------------------------------------------------------------------------

/**
 * RSA-OAEP-SHA256 decrypt the one-time AES key.
 *
 * CRITICAL: Uses phpseclib v3, NOT openssl_private_decrypt().
 * PHP's native openssl_private_decrypt() with OPENSSL_PKCS1_OAEP_PADDING
 * uses SHA-1 for the OAEP hash. Monime encrypts with SHA-256.
 * Using the native function WILL fail with a decryption error.
 */
function decryptAesKey(string $encryptedKey): string {
    global $privateKey;
    return $privateKey->decrypt($encryptedKey);
}

/**
 * AES-128-GCM decrypt the exchange payload.
 *
 * Blob layout: [1 byte IV length][12 bytes IV][ciphertext][16 bytes GCM auth tag]
 * PHP requires the auth tag to be split off manually.
 */
function decryptExchangeData(string $encryptedData, string $aesKey): array {
    $ivLength = ord($encryptedData[0]); // always 12
    $iv = substr($encryptedData, 1, $ivLength);
    $remainder = substr($encryptedData, 1 + $ivLength);

    // Split off the 16-byte GCM auth tag from the end
    $ciphertext = substr($remainder, 0, -16);
    $tag = substr($remainder, -16);

    $decrypted = openssl_decrypt(
        $ciphertext,
        'aes-128-gcm',
        $aesKey,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($decrypted === false) {
        throw new \RuntimeException('AES-GCM decryption failed: ' . openssl_error_string());
    }

    return json_decode($decrypted, true);
}

/**
 * AES-128-GCM encrypt the response with a fresh IV.
 *
 * Returns base64-encoded blob: [1 byte IV length][12 bytes IV][ciphertext][16 bytes auth tag]
 */
function encryptResponse(array $response, string $aesKey): string {
    $iv = openssl_random_pseudo_bytes(12); // fresh IV for each response
    $tag = '';

    $ciphertext = openssl_encrypt(
        json_encode($response),
        'aes-128-gcm',
        $aesKey,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',   // no AAD
        16    // tag length
    );

    if ($ciphertext === false) {
        throw new \RuntimeException('AES-GCM encryption failed: ' . openssl_error_string());
    }

    // Build blob: [iv_length (1 byte)][iv][ciphertext][tag]
    $blob = chr(strlen($iv)) . $iv . $ciphertext . $tag;
    return base64_encode($blob);
}

/**
 * Full request decryption pipeline.
 * Returns [aesKey, exchangeRequest].
 */
function decryptRequest(array $body): array {
    $encryptedKey = base64_decode($body['encryptedAesKey']);
    $encryptedData = base64_decode($body['encryptedExchangeData']);

    $aesKey = decryptAesKey($encryptedKey);
    $exchangeRequest = decryptExchangeData($encryptedData, $aesKey);

    return [$aesKey, $exchangeRequest];
}

// ---------------------------------------------------------------------------
// 3. Flow handler — mirrors the security-test flow
// ---------------------------------------------------------------------------

function handleExchange(array $exchangeRequest): array {
    $currentPage = $exchangeRequest['currentPage'] ?? '';

    switch ($currentPage) {
        case 'security_test_start':
            return [
                'action' => 'navigate',
                'pageId' => 'security_test_menu',
                'pageData' => [
                    'items' => [
                        ['label' => 'Continue', 'value' => 'continue'],
                        ['label' => 'Cancel', 'value' => 'cancel'],
                    ],
                    'message' => 'Security test flow (PHP). Select an option.',
                ],
            ];

        case 'security_test_menu':
            $flowData = $exchangeRequest['flowData'] ?? [];
            $value = strtolower(trim($flowData['security_test_menu'] ?? ''));

            if ($value === 'continue') {
                return [
                    'action' => 'navigate',
                    'pageId' => 'security_test_result',
                    'pageData' => [
                        'message' => 'You chose Continue. Security test completed successfully.',
                    ],
                ];
            }

            if ($value === 'cancel') {
                return [
                    'action' => 'stop',
                    'message' => 'Security test cancelled.',
                ];
            }

            return [
                'action' => 'stop',
                'message' => 'Invalid option. Please try again.',
            ];

        case 'security_test_result':
            return [
                'action' => 'stop',
                'message' => 'Thank you for using the security test flow (PHP).',
            ];

        default:
            return [
                'action' => 'stop',
                'message' => 'Unknown page: ' . $currentPage,
            ];
    }
}

// ---------------------------------------------------------------------------
// 4. Request handler
// ---------------------------------------------------------------------------

// Handle GET for health check
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'ok',
        'language' => 'php',
        'service' => 'ussd-flow-exchange',
        'encryption' => 'RSA-OAEP-SHA256 + AES-128-GCM',
        'key_loaded' => $privateKey !== null,
    ]);
    exit;
}

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['action' => 'stop', 'message' => 'Method not allowed']);
    exit;
}

try {
    // Read request body
    $rawBody = file_get_contents('php://input');
    $body = json_decode($rawBody, true);

    if ($body === null) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['action' => 'stop', 'message' => 'Invalid JSON']);
        exit;
    }

    // Check if request is encrypted
    $isEncrypted = isset($body['encryptedAesKey'])
        && isset($body['encryptedExchangeData'])
        && is_string($body['encryptedAesKey'])
        && is_string($body['encryptedExchangeData']);

    $aesKey = null;
    $exchangeRequest = null;

    if ($isEncrypted && $privateKey !== null) {
        // Encrypted request path
        try {
            [$aesKey, $exchangeRequest] = decryptRequest($body);
            $sessionId = $exchangeRequest['global']['sessionId'] ?? 'N/A';
            $page = $exchangeRequest['currentPage'] ?? 'N/A';
            error_log("[Exchange] Decryption OK — session: {$sessionId}, page: {$page}");
        } catch (\Exception $e) {
            error_log('[Exchange] Decryption FAILED: ' . $e->getMessage());
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['action' => 'stop', 'message' => 'Decryption failed']);
            exit;
        }
    } elseif (isset($body['currentPage']) && isset($body['global'])) {
        // Plain-text request path
        $exchangeRequest = $body;
        $page = $exchangeRequest['currentPage'] ?? 'N/A';
        error_log("[Exchange] Plain request — page: {$page}");
    } else {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['action' => 'stop', 'message' => 'Invalid request body']);
        exit;
    }

    // Process the exchange
    $response = handleExchange($exchangeRequest);

    // Send response
    if ($aesKey !== null) {
        // Encrypt the response
        $encrypted = encryptResponse($response, $aesKey);
        header('Content-Type: text/plain');
        echo $encrypted;
    } else {
        header('Content-Type: application/json');
        echo json_encode($response);
    }

} catch (\Exception $e) {
    error_log('[Exchange] Unhandled error: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['action' => 'stop', 'message' => 'Internal server error']);
}
