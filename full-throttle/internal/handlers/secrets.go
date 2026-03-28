package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/db"
	"github.com/fullthrottle/platform/internal/middleware"
	"github.com/fullthrottle/platform/internal/models"
	"github.com/fullthrottle/platform/internal/services"
)

type SecretHandler struct {
	k8sSvc  *services.K8sService
	queries *db.Queries
	cfg     *config.Config
}

func NewSecretHandler(k8sSvc *services.K8sService, queries *db.Queries, cfg *config.Config) *SecretHandler {
	return &SecretHandler{k8sSvc: k8sSvc, queries: queries, cfg: cfg}
}

func (h *SecretHandler) List(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	userID := middleware.GetUserID(r)
	userRole := middleware.GetUserRole(r)

	var secrets []models.Secret
	var err error

	// BUG-067: Viewer role can list all secrets including values (CWE-862, CVSS 7.5, HIGH, Tier 2)
	if userRole == "admin" || userRole == "operator" || userRole == "viewer" {
		secrets, err = h.queries.ListSecrets(namespace)
	} else {
		secrets, err = h.queries.ListUserSecrets(namespace, userID)
	}

	if err != nil {
		http.Error(w, `{"error":"failed to list secrets"}`, http.StatusInternalServerError)
		return
	}

	// BUG-068: Secret values returned in plaintext in list response (CWE-312, CVSS 7.5, HIGH, Tier 2)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: secrets})
}

func (h *SecretHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid secret ID"}`, http.StatusBadRequest)
		return
	}

	secret, err := h.queries.GetSecret(id)
	if err != nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	// BUG-069: No ownership check — any authenticated user can read any secret (CWE-639, CVSS 8.6, CRITICAL, Tier 1)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: secret})
}

func (h *SecretHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserID(r)

	// BUG-070: Encryption uses ECB mode (deterministic, pattern-preserving) (CWE-327, CVSS 5.9, TRICKY, Tier 6)
	encrypted, err := h.encryptSecret(req.Value)
	if err != nil {
		log.Printf("Encryption failed, storing plaintext: %v", err)
		// BUG-071: Falls back to storing plaintext if encryption fails (CWE-311, CVSS 7.5, HIGH, Tier 2)
		encrypted = req.Value
	}

	secret, err := h.queries.CreateSecret(req.Name, req.Namespace, encrypted, req.Type, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to create secret: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Also create in K8s
	if err := h.k8sSvc.CreateSecret(req.Name, req.Namespace, map[string]string{
		req.Name: req.Value,
	}); err != nil {
		// BUG-072: K8s secret creation error logged with the secret value (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
		log.Printf("Failed to create K8s secret %s: %v (value=%s)", req.Name, err, req.Value)
	}

	h.queries.CreateAuditLog(userID, "secret_create", req.Name, fmt.Sprintf("ns=%s type=%s", req.Namespace, req.Type))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: secret})
}

func (h *SecretHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid secret ID"}`, http.StatusBadRequest)
		return
	}

	var req models.SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetSecret(id)
	if err != nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	userID := middleware.GetUserID(r)

	// BUG-073: No ownership check on update — any user can overwrite any secret (CWE-862, CVSS 8.6, CRITICAL, Tier 1)

	encrypted, err := h.encryptSecret(req.Value)
	if err != nil {
		encrypted = req.Value
	}

	if err := h.queries.UpdateSecret(id, encrypted); err != nil {
		http.Error(w, `{"error":"failed to update secret"}`, http.StatusInternalServerError)
		return
	}

	// Update in K8s
	h.k8sSvc.UpdateSecret(existing.Name, existing.Namespace, map[string]string{
		existing.Name: req.Value,
	})

	h.queries.CreateAuditLog(userID, "secret_update", fmt.Sprintf("%d", id), "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *SecretHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid secret ID"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetSecret(id)
	if err != nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	userID := middleware.GetUserID(r)

	if err := h.queries.DeleteSecret(id); err != nil {
		http.Error(w, `{"error":"failed to delete secret"}`, http.StatusInternalServerError)
		return
	}

	// BUG-074: Error from K8s secret deletion not checked (CWE-252, CVSS 3.7, BEST_PRACTICE, Tier 5)
	h.k8sSvc.DeleteSecret(existing.Name, existing.Namespace)

	h.queries.CreateAuditLog(userID, "secret_delete", fmt.Sprintf("%d", id), "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

// BUG-070 implementation: ECB mode encryption — each block encrypted independently (CWE-327, CVSS 5.9, TRICKY, Tier 6)
func (h *SecretHandler) encryptSecret(plaintext string) (string, error) {
	key := []byte(h.cfg.EncryptionKey)
	if len(key) > 32 {
		key = key[:32]
	}
	for len(key) < 32 {
		key = append(key, 0)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// BUG-075: Static IV (all zeros) — makes encryption deterministic and vulnerable to analysis (CWE-329, CVSS 5.9, TRICKY, Tier 6)
	iv := make([]byte, aes.BlockSize)

	plainBytes := []byte(plaintext)
	// PKCS7 padding
	padding := aes.BlockSize - len(plainBytes)%aes.BlockSize
	for i := 0; i < padding; i++ {
		plainBytes = append(plainBytes, byte(padding))
	}

	ciphertext := make([]byte, len(plainBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plainBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
