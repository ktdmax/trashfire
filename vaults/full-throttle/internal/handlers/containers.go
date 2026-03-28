package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fullthrottle/platform/internal/db"
	"github.com/fullthrottle/platform/internal/middleware"
	"github.com/fullthrottle/platform/internal/models"
	"github.com/fullthrottle/platform/internal/services"
)

type ContainerHandler struct {
	dockerSvc *services.DockerService
	queries   *db.Queries
}

func NewContainerHandler(dockerSvc *services.DockerService, queries *db.Queries) *ContainerHandler {
	return &ContainerHandler{dockerSvc: dockerSvc, queries: queries}
}

func (h *ContainerHandler) List(w http.ResponseWriter, r *http.Request) {
	// BUG-049: No authorization check — any authenticated user can list all containers (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
	containers, err := h.dockerSvc.ListContainers()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list containers: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: containers})
}

func (h *ContainerHandler) Get(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	// BUG-050: IDOR — no ownership check, any user can access any container (CWE-639, CVSS 6.5, HIGH, Tier 2)
	container, err := h.dockerSvc.GetContainer(containerID)
	if err != nil {
		http.Error(w, `{"error":"container not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: container})
}

func (h *ContainerHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.CreateContainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// BUG-051: No image whitelist — user can pull and run any Docker image (CWE-829, CVSS 8.1, HIGH, Tier 2)

	// BUG-052: Volume mounts not restricted — can mount host filesystem (CWE-22, CVSS 8.6, HIGH, Tier 2)
	for _, vol := range req.Volumes {
		parts := strings.Split(vol, ":")
		if len(parts) >= 2 {
			log.Printf("Mounting volume: %s -> %s", parts[0], parts[1])
		}
	}

	userID := middleware.GetUserID(r)
	container, err := h.dockerSvc.CreateContainer(req, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to create container: %v"}`, err), http.StatusInternalServerError)
		return
	}

	h.queries.CreateAuditLog(userID, "container_create", container.ID, fmt.Sprintf("image=%s", req.Image))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: container})
}

func (h *ContainerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r)

	// BUG-053: No ownership or permission check before container deletion (CWE-862, CVSS 7.5, HIGH, Tier 2)
	if err := h.dockerSvc.DeleteContainer(containerID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to delete container: %v"}`, err), http.StatusInternalServerError)
		return
	}

	h.queries.CreateAuditLog(userID, "container_delete", containerID, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *ContainerHandler) Exec(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	var req models.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	req.ContainerID = containerID

	// BUG-054: Command injection via container exec — user-supplied command passed to shell (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
	cmdStr := strings.Join(req.Cmd, " ")
	cmd := exec.Command("docker", "exec", containerID, "sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"exec failed: %v, output: %s"}`, err, string(output)), http.StatusInternalServerError)
		return
	}

	userID := middleware.GetUserID(r)
	// BUG-055: Audit log contains full executed command — can leak secrets passed as args (CWE-532, CVSS 4.0, LOW, Tier 4)
	h.queries.CreateAuditLog(userID, "container_exec", containerID, fmt.Sprintf("cmd=%s output=%s", cmdStr, string(output)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: map[string]string{"output": string(output)}})
}

func (h *ContainerHandler) Logs(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	// BUG-056: Path traversal in log file path — containerID not sanitized (CWE-22, CVSS 7.5, HIGH, Tier 2)
	logPath := r.URL.Query().Get("path")
	if logPath == "" {
		logPath = fmt.Sprintf("/var/log/containers/%s.log", containerID)
	}

	// BUG-057: Arbitrary file read via path parameter (CWE-22, CVSS 8.6, HIGH, Tier 2)
	file, err := os.Open(logPath)
	if err != nil {
		http.Error(w, `{"error":"log file not found"}`, http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/plain")
	io.Copy(w, file)
}

func (h *ContainerHandler) Start(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	if err := h.dockerSvc.StartContainer(containerID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *ContainerHandler) Stop(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	if err := h.dockerSvc.StopContainer(containerID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

// RH-003: exec.Command with hardcoded arguments only — this looks like command injection
// but the arguments are all constants, making it safe.
func (h *ContainerHandler) pruneStoppedContainers() error {
	cmd := exec.Command("docker", "container", "prune", "--force", "--filter", "until=24h")
	return cmd.Run()
}

// BUG-058: SSRF — user-supplied URL fetched without validation for container image metadata (CWE-918, CVSS 7.5, HIGH, Tier 2)
func (h *ContainerHandler) fetchImageManifest(imageURL string) ([]byte, error) {
	resp, err := http.Get(imageURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// BUG-059: Insecure temp file creation with predictable name (CWE-377, CVSS 5.5, MEDIUM, Tier 3)
func (h *ContainerHandler) writeContainerConfig(containerID string, config []byte) error {
	tmpPath := filepath.Join("/tmp", fmt.Sprintf("container_%s.json", containerID))
	return os.WriteFile(tmpPath, config, 0666)
}
