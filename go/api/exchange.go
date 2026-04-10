// Package handler implements a Monime USSD Flow Exchange Server in Go.
//
// It implements the full hybrid RSA-OAEP + AES-128-GCM encryption protocol
// for receiving and responding to Monime USSD flow exchange requests.
//
// Deploy to Vercel as a Go serverless function.
package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Global contains session and subscriber information.
type Global struct {
	SessionID        string `json:"sessionId"`
	NetworkName      string `json:"networkName"`
	SubscriberID     string `json:"subscriberId"`
	SubscriberMsisdn string `json:"subscriberMsisdn"`
}

// ExchangeRequest is the decrypted USSD exchange request payload.
type ExchangeRequest struct {
	Global      Global            `json:"global"`
	FlowData    map[string]string `json:"flowData"`
	CurrentPage string            `json:"currentPage"`
}

// ExchangeResponse is the response sent back to Monime.
type ExchangeResponse struct {
	Action   string                 `json:"action"`
	Message  string                 `json:"message,omitempty"`
	PageID   string                 `json:"pageId,omitempty"`
	PageData map[string]interface{} `json:"pageData,omitempty"`
}

// EncryptedRequest is the wire format for encrypted exchange requests.
type EncryptedRequest struct {
	EncryptedAesKey       string `json:"encryptedAesKey"`
	EncryptedExchangeData string `json:"encryptedExchangeData"`
}

// HealthResponse is returned for GET requests.
type HealthResponse struct {
	Status     string `json:"status"`
	Language   string `json:"language"`
	Service    string `json:"service"`
	Encryption string `json:"encryption"`
	KeyLoaded  bool   `json:"key_loaded"`
}

// ---------------------------------------------------------------------------
// Private key (loaded once at cold-start)
// ---------------------------------------------------------------------------

var privateKey *rsa.PrivateKey

func init() {
	rawPem := os.Getenv("MONIME_RSA_PRIVATE_KEY")
	if rawPem == "" {
		log.Println("[Exchange] MONIME_RSA_PRIVATE_KEY not set")
		return
	}

	// Normalize: strip surrounding quotes, replace literal \n
	pemStr := strings.TrimSpace(rawPem)
	if strings.HasPrefix(pemStr, "\"") && strings.HasSuffix(pemStr, "\"") {
		pemStr = pemStr[1 : len(pemStr)-1]
	}
	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		log.Println("[Exchange] Failed to decode PEM block")
		return
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("[Exchange] Failed to parse private key: %v\n", err)
		return
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Println("[Exchange] Key is not RSA")
		return
	}

	privateKey = rsaKey
	log.Println("[Exchange] Private key loaded successfully")
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

// decryptAesKey uses RSA-OAEP-SHA256 to unwrap the one-time AES key.
func decryptAesKey(encryptedKey []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
}

// decryptExchangeData decrypts the AES-128-GCM encrypted payload.
//
// Blob layout: [1 byte IV length][12 bytes IV][ciphertext][16 bytes GCM auth tag]
// Go's GCM expects the tag appended to the ciphertext, which matches the blob format.
func decryptExchangeData(encryptedData, aesKey []byte) (*ExchangeRequest, error) {
	if len(encryptedData) < 1+12+16 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	ivLength := int(encryptedData[0]) // always 12
	iv := encryptedData[1 : 1+ivLength]
	ciphertextWithTag := encryptedData[1+ivLength:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}

	decrypted, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	var req ExchangeRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	return &req, nil
}

// encryptResponse encrypts the response with AES-128-GCM using a fresh IV.
//
// Returns base64-encoded blob: [1 byte IV length][12 bytes IV][ciphertext + 16 bytes auth tag]
func encryptResponse(response *ExchangeResponse, aesKey []byte) (string, error) {
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("JSON marshal: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM: %w", err)
	}

	iv := make([]byte, 12) // fresh IV for each response
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("IV generation: %w", err)
	}

	// Seal appends the GCM auth tag to the ciphertext
	encrypted := gcm.Seal(nil, iv, responseJSON, nil)

	// Build blob: [iv_length (1 byte)][iv][ciphertext + tag]
	blob := make([]byte, 1+len(iv)+len(encrypted))
	blob[0] = byte(len(iv))
	copy(blob[1:], iv)
	copy(blob[1+len(iv):], encrypted)

	return base64.StdEncoding.EncodeToString(blob), nil
}

// decryptRequest performs the full request decryption pipeline.
func decryptRequest(encReq *EncryptedRequest) ([]byte, *ExchangeRequest, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(encReq.EncryptedAesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode AES key: %w", err)
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encReq.EncryptedExchangeData)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode exchange data: %w", err)
	}

	aesKey, err := decryptAesKey(encryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA decrypt AES key: %w", err)
	}

	exchangeReq, err := decryptExchangeData(encryptedData, aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("AES decrypt payload: %w", err)
	}

	return aesKey, exchangeReq, nil
}

// ---------------------------------------------------------------------------
// Flow handler — mirrors the security-test flow
// ---------------------------------------------------------------------------

func handleExchange(req *ExchangeRequest) *ExchangeResponse {
	switch req.CurrentPage {
	case "security_test_start":
		return &ExchangeResponse{
			Action: "navigate",
			PageID: "security_test_menu",
			PageData: map[string]interface{}{
				"items": []map[string]string{
					{"label": "Continue", "value": "continue"},
					{"label": "Cancel", "value": "cancel"},
				},
				"message": "Security test flow (Go). Select an option.",
			},
		}

	case "security_test_menu":
		value := strings.TrimSpace(strings.ToLower(req.FlowData["security_test_menu"]))

		if value == "continue" {
			return &ExchangeResponse{
				Action: "navigate",
				PageID: "security_test_result",
				PageData: map[string]interface{}{
					"message": "You chose Continue. Security test completed successfully.",
				},
			}
		}
		if value == "cancel" {
			return &ExchangeResponse{
				Action:  "stop",
				Message: "Security test cancelled.",
			}
		}
		return &ExchangeResponse{
			Action:  "stop",
			Message: "Invalid option. Please try again.",
		}

	case "security_test_result":
		return &ExchangeResponse{
			Action:  "stop",
			Message: "Thank you for using the security test flow (Go).",
		}

	default:
		return &ExchangeResponse{
			Action:  "stop",
			Message: fmt.Sprintf("Unknown page: %s", req.CurrentPage),
		}
	}
}

// ---------------------------------------------------------------------------
// Vercel serverless handler
// ---------------------------------------------------------------------------

// Handler is the Vercel serverless function entry point.
func Handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGet(w)
	case http.MethodPost:
		handlePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleGet(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{
		Status:     "ok",
		Language:   "go",
		Service:    "ussd-flow-exchange",
		Encryption: "RSA-OAEP-SHA256 + AES-128-GCM",
		KeyLoaded:  privateKey != nil,
	})
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var rawBody map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawBody); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Check if request is encrypted
	_, hasAesKey := rawBody["encryptedAesKey"]
	_, hasData := rawBody["encryptedExchangeData"]
	isEncrypted := hasAesKey && hasData

	var aesKey []byte
	var exchangeReq *ExchangeRequest

	if isEncrypted && privateKey != nil {
		// Encrypted request path
		var encReq EncryptedRequest
		if err := json.Unmarshal(bodyBytes, &encReq); err != nil {
			sendError(w, http.StatusBadRequest, "Invalid encrypted request format")
			return
		}

		aesKey, exchangeReq, err = decryptRequest(&encReq)
		if err != nil {
			log.Printf("[Exchange] Decryption FAILED: %v\n", err)
			sendError(w, http.StatusBadRequest, "Decryption failed")
			return
		}
		log.Printf("[Exchange] Decryption OK — session: %s, page: %s\n",
			exchangeReq.Global.SessionID, exchangeReq.CurrentPage)

	} else if _, hasPage := rawBody["currentPage"]; hasPage {
		// Plain-text request path
		exchangeReq = &ExchangeRequest{}
		if err := json.Unmarshal(bodyBytes, exchangeReq); err != nil {
			sendError(w, http.StatusBadRequest, "Invalid exchange request format")
			return
		}
		log.Printf("[Exchange] Plain request — session: %s, page: %s\n",
			exchangeReq.Global.SessionID, exchangeReq.CurrentPage)

	} else {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Process the exchange
	response := handleExchange(exchangeReq)

	// Send response
	if aesKey != nil {
		// Encrypt the response
		encrypted, err := encryptResponse(response, aesKey)
		if err != nil {
			log.Printf("[Exchange] Encryption FAILED: %v\n", err)
			sendError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(encrypted))
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ExchangeResponse{
		Action:  "stop",
		Message: message,
	})
}
