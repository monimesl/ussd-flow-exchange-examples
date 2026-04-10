package io.monime.exchange;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * Monime USSD Flow Exchange Server — Java
 *
 * Implements the full hybrid RSA-OAEP + AES-128-GCM encryption protocol
 * for receiving and responding to Monime USSD flow exchange requests.
 *
 * Uses only the Java standard library (no Spring Boot dependency).
 * Can be packaged as a Docker container for deployment.
 */
public class ExchangeHandler implements HttpHandler {

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final PrivateKey privateKey;

    public ExchangeHandler() {
        this.privateKey = loadPrivateKey();
    }

    // -----------------------------------------------------------------------
    // 1. Load RSA private key at startup
    // -----------------------------------------------------------------------

    private static PrivateKey loadPrivateKey() {
        String rawPem = System.getenv("MONIME_RSA_PRIVATE_KEY");
        if (rawPem == null || rawPem.isEmpty()) {
            System.out.println("[Exchange] MONIME_RSA_PRIVATE_KEY not set");
            return null;
        }

        try {
            // Normalize: strip surrounding quotes, replace literal \n
            String pemStr = rawPem.trim();
            if (pemStr.startsWith("\"") && pemStr.endsWith("\"")) {
                pemStr = pemStr.substring(1, pemStr.length() - 1);
            }
            pemStr = pemStr.replace("\\n", "\n");

            // Strip PEM headers and whitespace
            String base64Key = pemStr
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            System.out.println("[Exchange] Private key loaded successfully");
            return key;

        } catch (Exception e) {
            System.out.println("[Exchange] Failed to load private key: " + e.getMessage());
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // 2. Crypto helpers
    // -----------------------------------------------------------------------

    /**
     * RSA-OAEP-SHA256 decrypt the one-time AES key.
     *
     * CRITICAL: Must use OAEPParameterSpec to explicitly set SHA-256 for
     * both the OAEP hash AND the MGF1 hash. Java's default
     * "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" uses SHA-1 for MGF1,
     * which does NOT match Monime's SHA-256 for both.
     */
    private byte[] decryptAesKey(byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",                        // OAEP hash algorithm
                "MGF1",                           // Mask generation function
                MGF1ParameterSpec.SHA256,          // MGF1 hash — MUST be SHA-256
                PSource.PSpecified.DEFAULT         // No label
        );

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        return cipher.doFinal(encryptedKey);
    }

    /**
     * AES-128-GCM decrypt the exchange payload.
     *
     * Blob layout: [1 byte IV length][12 bytes IV][ciphertext][16 bytes GCM auth tag]
     * Java's AES/GCM/NoPadding handles the auth tag automatically when
     * it is appended to the ciphertext.
     */
    private Map<String, Object> decryptExchangeData(byte[] encryptedData, byte[] aesKey) throws Exception {
        int ivLength = encryptedData[0] & 0xFF; // always 12
        byte[] iv = Arrays.copyOfRange(encryptedData, 1, 1 + ivLength);
        byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, 1 + ivLength, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv)
        );

        byte[] decrypted = cipher.doFinal(ciphertextWithTag);
        String json = new String(decrypted, StandardCharsets.UTF_8);

        return parseJson(json);
    }

    /**
     * AES-128-GCM encrypt the response with a fresh IV.
     *
     * Returns base64-encoded blob: [1 byte IV length][12 bytes IV][ciphertext + 16 bytes auth tag]
     */
    private String encryptResponse(Map<String, Object> response, byte[] aesKey) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv)
        );

        byte[] responseJson = toJson(response).getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.doFinal(responseJson);

        // Build blob: [iv_length (1 byte)][iv][ciphertext + tag]
        byte[] blob = new byte[1 + iv.length + encrypted.length];
        blob[0] = (byte) iv.length;
        System.arraycopy(iv, 0, blob, 1, iv.length);
        System.arraycopy(encrypted, 0, blob, 1 + iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(blob);
    }

    // -----------------------------------------------------------------------
    // 3. Flow handler — mirrors the security-test flow
    // -----------------------------------------------------------------------

    private Map<String, Object> handleExchangeFlow(Map<String, Object> exchangeRequest) {
        String currentPage = (String) exchangeRequest.getOrDefault("currentPage", "");

        switch (currentPage) {
            case "security_test_start": {
                List<Map<String, String>> items = new ArrayList<>();
                items.add(Map.of("label", "Continue", "value", "continue"));
                items.add(Map.of("label", "Cancel", "value", "cancel"));

                return Map.of(
                        "action", "navigate",
                        "pageId", "security_test_menu",
                        "pageData", Map.of(
                                "items", items,
                                "message", "Security test flow (Java). Select an option."
                        )
                );
            }

            case "security_test_menu": {
                @SuppressWarnings("unchecked")
                Map<String, Object> flowData = (Map<String, Object>) exchangeRequest.getOrDefault("flowData", Map.of());
                String value = String.valueOf(flowData.getOrDefault("security_test_menu", "")).trim().toLowerCase();

                if ("continue".equals(value)) {
                    return Map.of(
                            "action", "navigate",
                            "pageId", "security_test_result",
                            "pageData", Map.of(
                                    "message", "You chose Continue. Security test completed successfully."
                            )
                    );
                }
                if ("cancel".equals(value)) {
                    return Map.of(
                            "action", "stop",
                            "message", "Security test cancelled."
                    );
                }
                return Map.of(
                        "action", "stop",
                        "message", "Invalid option. Please try again."
                );
            }

            case "security_test_result":
                return Map.of(
                        "action", "stop",
                        "message", "Thank you for using the security test flow (Java)."
                );

            default:
                return Map.of(
                        "action", "stop",
                        "message", "Unknown page: " + currentPage
                );
        }
    }

    // -----------------------------------------------------------------------
    // 4. HTTP handler
    // -----------------------------------------------------------------------

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();

            if ("GET".equalsIgnoreCase(method)) {
                handleGet(exchange);
                return;
            }

            if (!"POST".equalsIgnoreCase(method)) {
                sendResponse(exchange, 405, "application/json",
                        "{\"action\":\"stop\",\"message\":\"Method not allowed\"}");
                return;
            }

            handlePostRequest(exchange);

        } catch (Exception e) {
            System.out.println("[Exchange] Unhandled error: " + e.getMessage());
            e.printStackTrace();
            sendResponse(exchange, 500, "application/json",
                    "{\"action\":\"stop\",\"message\":\"Internal server error\"}");
        }
    }

    private void handleGet(HttpExchange exchange) throws IOException {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("status", "ok");
        health.put("language", "java");
        health.put("service", "ussd-flow-exchange");
        health.put("encryption", "RSA-OAEP-SHA256 + AES-128-GCM");
        health.put("key_loaded", privateKey != null);

        sendResponse(exchange, 200, "application/json", toJson(health));
    }

    private void handlePostRequest(HttpExchange exchange) throws IOException {
        // Read request body
        String rawBody;
        try (InputStream is = exchange.getRequestBody()) {
            rawBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Parse JSON
        Map<String, Object> body;
        try {
            body = parseJson(rawBody);
        } catch (Exception e) {
            sendResponse(exchange, 400, "application/json",
                    "{\"action\":\"stop\",\"message\":\"Invalid JSON\"}");
            return;
        }

        // Check if request is encrypted
        boolean isEncrypted = body.containsKey("encryptedAesKey")
                && body.containsKey("encryptedExchangeData")
                && body.get("encryptedAesKey") instanceof String
                && body.get("encryptedExchangeData") instanceof String;

        byte[] aesKey = null;
        Map<String, Object> exchangeRequest;

        if (isEncrypted && privateKey != null) {
            try {
                byte[] encryptedKey = Base64.getDecoder().decode((String) body.get("encryptedAesKey"));
                byte[] encryptedData = Base64.getDecoder().decode((String) body.get("encryptedExchangeData"));

                aesKey = decryptAesKey(encryptedKey);
                exchangeRequest = decryptExchangeData(encryptedData, aesKey);

                System.out.printf("[Exchange] Decryption OK — page: %s%n",
                        exchangeRequest.getOrDefault("currentPage", "N/A"));

            } catch (Exception e) {
                System.out.println("[Exchange] Decryption FAILED: " + e.getMessage());
                sendResponse(exchange, 400, "application/json",
                        "{\"action\":\"stop\",\"message\":\"Decryption failed\"}");
                return;
            }

        } else if (body.containsKey("currentPage") && body.containsKey("global")) {
            exchangeRequest = body;
            System.out.printf("[Exchange] Plain request — page: %s%n",
                    exchangeRequest.getOrDefault("currentPage", "N/A"));

        } else {
            sendResponse(exchange, 400, "application/json",
                    "{\"action\":\"stop\",\"message\":\"Invalid request body\"}");
            return;
        }

        // Process the exchange
        Map<String, Object> response = handleExchangeFlow(exchangeRequest);

        // Send response
        if (aesKey != null) {
            try {
                String encrypted = encryptResponse(response, aesKey);
                sendResponse(exchange, 200, "text/plain", encrypted);
            } catch (Exception e) {
                System.out.println("[Exchange] Encryption FAILED: " + e.getMessage());
                sendResponse(exchange, 500, "application/json",
                        "{\"action\":\"stop\",\"message\":\"Encryption failed\"}");
            }
        } else {
            sendResponse(exchange, 200, "application/json", toJson(response));
        }
    }

    private void sendResponse(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // -----------------------------------------------------------------------
    // 5. Minimal JSON helpers (no external dependencies)
    // -----------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseJson(String json) {
        json = json.trim();
        if (!json.startsWith("{")) {
            throw new RuntimeException("Expected JSON object");
        }
        // Use a simple recursive-descent parser for basic JSON
        return (Map<String, Object>) new SimpleJsonParser(json).parse();
    }

    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        appendJson(sb, map);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void appendJson(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append('"');
            String s = (String) value;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default: sb.append(c);
                }
            }
            sb.append('"');
        } else if (value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) value;
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                appendJson(sb, entry.getKey());
                sb.append(':');
                appendJson(sb, entry.getValue());
            }
            sb.append('}');
        } else if (value instanceof List) {
            List<Object> list = (List<Object>) value;
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                appendJson(sb, list.get(i));
            }
            sb.append(']');
        } else {
            sb.append('"').append(value.toString()).append('"');
        }
    }

    // -----------------------------------------------------------------------
    // 6. Entry point
    // -----------------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        int port = 3000;
        String portStr = System.getenv("PORT");
        if (portStr != null && !portStr.isEmpty()) {
            port = Integer.parseInt(portStr);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/exchange", new ExchangeHandler());
        server.setExecutor(null);
        server.start();

        System.out.printf("[Exchange] Java server started on port %d%n", port);
    }
}
