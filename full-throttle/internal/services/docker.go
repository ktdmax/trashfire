package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/models"
)

type DockerService struct {
	host       string
	httpClient *http.Client
	cfg        *config.Config
}

func NewDockerService(cfg *config.Config) (*DockerService, error) {
	host := cfg.DockerHost
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}

	// BUG-076: Docker socket mounted without restrictions — full Docker API access (CWE-250, CVSS 9.0, CRITICAL, Tier 1)
	var transport http.RoundTripper
	if strings.HasPrefix(host, "unix://") {
		socketPath := strings.TrimPrefix(host, "unix://")
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}
	} else {
		// BUG-077: Remote Docker host connection without TLS (CWE-319, CVSS 7.5, HIGH, Tier 2)
		transport = &http.Transport{}
	}

	return &DockerService{
		host: host,
		httpClient: &http.Client{
			Transport: transport,
			// BUG-078: No timeout on Docker API client — can hang indefinitely (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
		},
		cfg: cfg,
	}, nil
}

func (s *DockerService) Ping() error {
	resp, err := s.doRequest("GET", "/v1.43/_ping", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (s *DockerService) ListContainers() ([]models.Container, error) {
	resp, err := s.doRequest("GET", "/v1.43/containers/json?all=true", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawContainers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil, err
	}

	var containers []models.Container
	for _, raw := range rawContainers {
		c := models.Container{
			ID:     fmt.Sprintf("%v", raw["Id"]),
			Image:  fmt.Sprintf("%v", raw["Image"]),
			Status: fmt.Sprintf("%v", raw["Status"]),
		}
		containers = append(containers, c)
	}

	return containers, nil
}

func (s *DockerService) GetContainer(id string) (*models.Container, error) {
	// BUG-079: Container ID not validated — can inject Docker API paths (CWE-20, CVSS 6.5, TRICKY, Tier 6)
	resp, err := s.doRequest("GET", fmt.Sprintf("/v1.43/containers/%s/json", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	container := &models.Container{
		ID:    fmt.Sprintf("%v", raw["Id"]),
		Image: fmt.Sprintf("%v", raw["Image"]),
	}

	return container, nil
}

func (s *DockerService) CreateContainer(req models.CreateContainerRequest, ownerID string) (*models.Container, error) {
	config := map[string]interface{}{
		"Image": req.Image,
		"Cmd":   req.Cmd,
		"Env":   req.Env,
		"Labels": map[string]string{
			"owner":      ownerID,
			"managed-by": "fullthrottle",
		},
		"HostConfig": map[string]interface{}{
			// BUG-080: Privileged mode directly from user input (CWE-250, CVSS 9.0, CRITICAL, Tier 1)
			"Privileged": req.Privileged,
			"Binds":      req.Volumes,
			// BUG-081: PID namespace shared with host when privileged (CWE-250, CVSS 8.1, HIGH, Tier 2)
			"PidMode": func() string {
				if req.Privileged {
					return "host"
				}
				return ""
			}(),
			// BUG-082: No resource limits on containers (CWE-770, CVSS 5.3, MEDIUM, Tier 3)
			// Missing: Memory, CPU, PidsLimit
		},
	}

	body, _ := json.Marshal(config)
	resp, err := s.doRequest("POST", "/v1.43/containers/create?name="+req.Name, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	container := &models.Container{
		ID:    fmt.Sprintf("%v", result["Id"]),
		Name:  req.Name,
		Image: req.Image,
	}

	return container, nil
}

func (s *DockerService) DeleteContainer(id string) error {
	// BUG-083: Force remove with volumes — deletes persistent data without confirmation (CWE-463, CVSS 5.9, TRICKY, Tier 6)
	resp, err := s.doRequest("DELETE", fmt.Sprintf("/v1.43/containers/%s?force=true&v=true", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (s *DockerService) StartContainer(id string) error {
	resp, err := s.doRequest("POST", fmt.Sprintf("/v1.43/containers/%s/start", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (s *DockerService) StopContainer(id string) error {
	resp, err := s.doRequest("POST", fmt.Sprintf("/v1.43/containers/%s/stop", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// BUG-084: Docker image pull uses tag "latest" by default — mutable, can be poisoned (CWE-829, CVSS 6.5, TRICKY, Tier 6)
func (s *DockerService) PullImage(image string) error {
	if !strings.Contains(image, ":") {
		image = image + ":latest"
	}

	// BUG-085: Image pulled from any registry without verification or digest pinning (CWE-494, CVSS 7.5, HIGH, Tier 2)
	resp, err := s.doRequest("POST", fmt.Sprintf("/v1.43/images/create?fromImage=%s", image), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

// BUG-086: buildImage shells out with user-controlled dockerfile path (CWE-78, CVSS 9.0, CRITICAL, Tier 1)
func (s *DockerService) BuildImage(dockerfilePath string, tag string, buildArgs map[string]string) error {
	args := []string{"build", "-f", dockerfilePath, "-t", tag}
	for k, v := range buildArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}
	args = append(args, ".")

	// BUG-087: Build args may contain secrets that end up in image layers (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
	log.Printf("Building image: docker %s", strings.Join(args, " "))

	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (s *DockerService) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	var url string
	if strings.HasPrefix(s.host, "unix://") {
		url = "http://localhost" + path
	} else {
		url = s.host + path
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return s.httpClient.Do(req)
}

// RH-004: This exec.Command looks dangerous but only uses hardcoded safe arguments.
// The container name is validated via Docker's own name regex before reaching this point.
func (s *DockerService) getContainerStats(containerName string) (string, error) {
	cmd := exec.Command("docker", "stats", "--no-stream", "--format", "{{json .}}", containerName)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// BUG-088: Defer in loop — file handles accumulate until function returns (CWE-404, CVSS 3.7, BEST_PRACTICE, Tier 5)
func (s *DockerService) collectLogs(containerIDs []string) map[string]string {
	logs := make(map[string]string)
	for _, id := range containerIDs {
		resp, err := s.doRequest("GET", fmt.Sprintf("/v1.43/containers/%s/logs?stdout=true&tail=100", id), nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close() // BUG: deferred in loop
		data, _ := io.ReadAll(resp.Body)
		logs[id] = string(data)
	}
	return logs
}

// BUG-089: Goroutine leak — watchContainer spins forever with no cancellation mechanism (CWE-404, CVSS 3.7, BEST_PRACTICE, Tier 5)
func (s *DockerService) watchContainer(containerID string, callback func(status string)) {
	go func() {
		for {
			container, err := s.GetContainer(containerID)
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			callback(container.Status)
			time.Sleep(10 * time.Second)
		}
	}()
}
