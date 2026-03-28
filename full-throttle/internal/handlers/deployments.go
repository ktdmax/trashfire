package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/fullthrottle/platform/internal/db"
	"github.com/fullthrottle/platform/internal/middleware"
	"github.com/fullthrottle/platform/internal/models"
	"github.com/fullthrottle/platform/internal/services"
)

type DeploymentHandler struct {
	k8sSvc  *services.K8sService
	queries *db.Queries
}

func NewDeploymentHandler(k8sSvc *services.K8sService, queries *db.Queries) *DeploymentHandler {
	return &DeploymentHandler{k8sSvc: k8sSvc, queries: queries}
}

func (h *DeploymentHandler) List(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	deployments, err := h.k8sSvc.ListDeployments(namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list deployments: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: deployments})
}

func (h *DeploymentHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid deployment ID"}`, http.StatusBadRequest)
		return
	}

	deployment, err := h.queries.GetDeployment(id)
	if err != nil {
		http.Error(w, `{"error":"deployment not found"}`, http.StatusNotFound)
		return
	}

	// BUG-060: IDOR — any authenticated user can view any deployment regardless of ownership (CWE-639, CVSS 6.5, HIGH, Tier 2)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: deployment})
}

func (h *DeploymentHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserID(r)

	// BUG-061: Raw YAML override allows arbitrary K8s resource injection (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
	if req.RawOverride != "" {
		var override map[string]interface{}
		if err := yaml.Unmarshal([]byte(req.RawOverride), &override); err != nil {
			http.Error(w, `{"error":"invalid YAML override"}`, http.StatusBadRequest)
			return
		}
		// The override is merged directly into the deployment spec
		log.Printf("Applying raw override for deployment %s: %v", req.Name, override)
	}

	// BUG-062: Namespace not validated — user can deploy to kube-system or other privileged namespaces (CWE-285, CVSS 8.1, HIGH, Tier 2)
	deployment, err := h.k8sSvc.CreateDeployment(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to create deployment: %v"}`, err), http.StatusInternalServerError)
		return
	}

	h.queries.CreateDeploymentRecord(req.Name, req.Namespace, req.Image, req.Replicas, userID)
	h.queries.CreateAuditLog(userID, "deployment_create", req.Name, fmt.Sprintf("ns=%s image=%s", req.Namespace, req.Image))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: deployment})
}

func (h *DeploymentHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid deployment ID"}`, http.StatusBadRequest)
		return
	}

	var req models.DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetDeployment(id)
	if err != nil {
		http.Error(w, `{"error":"deployment not found"}`, http.StatusNotFound)
		return
	}

	// BUG-063: No ownership check — any user can update any deployment (CWE-862, CVSS 7.5, HIGH, Tier 2)
	userID := middleware.GetUserID(r)

	if err := h.k8sSvc.UpdateDeployment(existing.Name, existing.Namespace, req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to update deployment: %v"}`, err), http.StatusInternalServerError)
		return
	}

	h.queries.UpdateDeploymentRecord(id, req.Image, req.Replicas)
	h.queries.CreateAuditLog(userID, "deployment_update", fmt.Sprintf("%d", id), fmt.Sprintf("image=%s replicas=%d", req.Image, req.Replicas))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *DeploymentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid deployment ID"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetDeployment(id)
	if err != nil {
		http.Error(w, `{"error":"deployment not found"}`, http.StatusNotFound)
		return
	}

	userID := middleware.GetUserID(r)

	if err := h.k8sSvc.DeleteDeployment(existing.Name, existing.Namespace); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to delete deployment: %v"}`, err), http.StatusInternalServerError)
		return
	}

	h.queries.DeleteDeploymentRecord(id)
	h.queries.CreateAuditLog(userID, "deployment_delete", fmt.Sprintf("%d", id), "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *DeploymentHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid deployment ID"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetDeployment(id)
	if err != nil {
		http.Error(w, `{"error":"deployment not found"}`, http.StatusNotFound)
		return
	}

	var req struct {
		// BUG-064: Rollback revision not validated — can specify revision 0 to reset to initial (possibly insecure) state (CWE-20, CVSS 5.9, TRICKY, Tier 6)
		Revision int64 `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if err := h.k8sSvc.RollbackDeployment(existing.Name, existing.Namespace, req.Revision); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"rollback failed: %v"}`, err), http.StatusInternalServerError)
		return
	}

	userID := middleware.GetUserID(r)
	h.queries.CreateAuditLog(userID, "deployment_rollback", fmt.Sprintf("%d", id), fmt.Sprintf("revision=%d", req.Revision))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *DeploymentHandler) Status(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid deployment ID"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetDeployment(id)
	if err != nil {
		http.Error(w, `{"error":"deployment not found"}`, http.StatusNotFound)
		return
	}

	status, err := h.k8sSvc.GetDeploymentStatus(existing.Name, existing.Namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to get status: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: status})
}

// BUG-065: Webhook deploy endpoint trusts payload without signature verification (CWE-347, CVSS 8.1, HIGH, Tier 2)
func (h *DeploymentHandler) WebhookDeploy(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Namespace  string `json:"namespace"`
		// BUG-066: Webhook can specify arbitrary deployment name, enabling hijacking of existing deployments (CWE-639, CVSS 7.5, HIGH, Tier 2)
		DeploymentName string `json:"deployment_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
		return
	}

	image := fmt.Sprintf("%s:%s", payload.Repository, payload.Tag)
	req := models.DeploymentRequest{
		Name:      payload.DeploymentName,
		Namespace: payload.Namespace,
		Image:     image,
		Replicas:  3,
	}

	if _, err := h.k8sSvc.CreateDeployment(req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"deploy failed: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}
