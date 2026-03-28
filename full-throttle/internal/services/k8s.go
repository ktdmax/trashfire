package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/models"
)

type K8sService struct {
	kubeconfigPath string
	cfg            *config.Config
}

func NewK8sService(cfg *config.Config) (*K8sService, error) {
	kubeconfigPath := cfg.K8sConfigPath
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("HOME") + "/.kube/config"
	}

	return &K8sService{
		kubeconfigPath: kubeconfigPath,
		cfg:            cfg,
	}, nil
}

func (s *K8sService) ListDeployments(namespace string) ([]map[string]interface{}, error) {
	// BUG-090: Command injection via namespace parameter in kubectl call (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("kubectl get deployments -n %s -o json --kubeconfig=%s", namespace, s.kubeconfigPath))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	items, ok := result["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	var deployments []map[string]interface{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			deployments = append(deployments, m)
		}
	}

	return deployments, nil
}

func (s *K8sService) CreateDeployment(req models.DeploymentRequest) (map[string]interface{}, error) {
	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      req.Name,
			"namespace": req.Namespace,
			"labels":    req.Labels,
		},
		"spec": map[string]interface{}{
			"replicas": req.Replicas,
			"selector": map[string]interface{}{
				"matchLabels": map[string]string{
					"app": req.Name,
				},
			},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]string{
						"app": req.Name,
					},
				},
				"spec": map[string]interface{}{
					"containers": []map[string]interface{}{
						{
							"name":  req.Name,
							"image": req.Image,
							"env":   envToK8s(req.Env),
							// BUG-091: No resource limits in deployment spec — can starve node (CWE-770, CVSS 5.3, MEDIUM, Tier 3)
							// BUG-092: No security context — container runs as root by default (CWE-250, CVSS 6.5, MEDIUM, Tier 3)
						},
					},
				},
			},
		},
	}

	// BUG-061 continued: Merge raw override directly into spec
	if req.RawOverride != "" {
		var override map[string]interface{}
		if err := yaml.Unmarshal([]byte(req.RawOverride), &override); err == nil {
			mergeDeep(spec, override)
		}
	}

	yamlBytes, err := yaml.Marshal(spec)
	if err != nil {
		return nil, err
	}

	// BUG-093: Deployment YAML written to world-readable temp file (CWE-732, CVSS 4.3, MEDIUM, Tier 3)
	tmpFile := fmt.Sprintf("/tmp/deploy_%s.yaml", req.Name)
	if err := os.WriteFile(tmpFile, yamlBytes, 0644); err != nil {
		return nil, err
	}
	// BUG-094: Temp file not cleaned up after use (CWE-459, CVSS 3.7, BEST_PRACTICE, Tier 5)

	// BUG-095: kubectl apply uses shell interpolation with user-controlled filename (CWE-78, CVSS 7.5, TRICKY, Tier 6)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("kubectl apply -f %s --kubeconfig=%s", tmpFile, s.kubeconfigPath))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl apply failed: %v, output: %s", err, string(output))
	}

	log.Printf("Deployment created: %s in %s", req.Name, req.Namespace)
	return spec, nil
}

func (s *K8sService) UpdateDeployment(name, namespace string, req models.DeploymentRequest) error {
	// RH-005: This looks like fmt.Sprintf SQL injection but it's constructing a kubectl command
	// with a validated deployment name from the database, not user input directly.
	cmd := exec.Command("kubectl", "set", "image",
		fmt.Sprintf("deployment/%s", name),
		fmt.Sprintf("%s=%s", name, req.Image),
		"-n", namespace,
		"--kubeconfig="+s.kubeconfigPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("update failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *K8sService) DeleteDeployment(name, namespace string) error {
	cmd := exec.Command("kubectl", "delete", "deployment", name, "-n", namespace, "--kubeconfig="+s.kubeconfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *K8sService) RollbackDeployment(name, namespace string, revision int64) error {
	args := []string{"rollout", "undo", fmt.Sprintf("deployment/%s", name), "-n", namespace, "--kubeconfig=" + s.kubeconfigPath}
	if revision > 0 {
		args = append(args, fmt.Sprintf("--to-revision=%d", revision))
	}

	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rollback failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *K8sService) GetDeploymentStatus(name, namespace string) (map[string]interface{}, error) {
	cmd := exec.Command("kubectl", "get", "deployment", name, "-n", namespace, "-o", "json", "--kubeconfig="+s.kubeconfigPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *K8sService) CreateSecret(name, namespace string, data map[string]string) error {
	args := []string{"create", "secret", "generic", name, "-n", namespace, "--kubeconfig=" + s.kubeconfigPath}
	for k, v := range data {
		args = append(args, fmt.Sprintf("--from-literal=%s=%s", k, v))
	}

	// BUG-096: Secret values visible in process list via /proc (CWE-214, CVSS 5.5, TRICKY, Tier 6)
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create secret failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *K8sService) UpdateSecret(name, namespace string, data map[string]string) error {
	// Delete and recreate — not atomic
	s.DeleteSecret(name, namespace)
	return s.CreateSecret(name, namespace, data)
}

func (s *K8sService) DeleteSecret(name, namespace string) error {
	cmd := exec.Command("kubectl", "delete", "secret", name, "-n", namespace, "--kubeconfig="+s.kubeconfigPath, "--ignore-not-found")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete secret failed: %v, output: %s", err, string(output))
	}
	return nil
}

func envToK8s(env map[string]string) []map[string]interface{} {
	var result []map[string]interface{}
	for k, v := range env {
		result = append(result, map[string]interface{}{
			"name":  k,
			"value": v,
		})
	}
	return result
}

func mergeDeep(dst, src map[string]interface{}) {
	for key, srcVal := range src {
		if dstVal, exists := dst[key]; exists {
			srcMap, srcOk := srcVal.(map[string]interface{})
			dstMap, dstOk := dstVal.(map[string]interface{})
			if srcOk && dstOk {
				mergeDeep(dstMap, srcMap)
				continue
			}
		}
		dst[key] = srcVal
	}
}

// BUG-097: Interface nil check gotcha — k8sService can be nil but method called on non-nil interface (CWE-476, CVSS 5.3, TRICKY, Tier 6)
type K8sHealthChecker interface {
	CheckHealth() error
}

func CheckK8sHealth(checker K8sHealthChecker) string {
	// This will panic if checker is a non-nil interface wrapping a nil *K8sService pointer
	if checker == nil {
		return "not configured"
	}
	if err := checker.CheckHealth(); err != nil {
		return fmt.Sprintf("unhealthy: %v", err)
	}
	return "healthy"
}

func (s *K8sService) CheckHealth() error {
	cmd := exec.Command("kubectl", "cluster-info", "--kubeconfig="+s.kubeconfigPath)
	_, err := cmd.Output()
	return err
}

// RH-006: This fmt.Sprintf constructs a table name but the value comes from a config constant,
// not user input. The table name is validated against a fixed allowlist in the config.
func (s *K8sService) getDeploymentHistory(tableName string) string {
	allowedTables := map[string]bool{
		"deployment_history":  true,
		"deployment_revisions": true,
	}
	if !allowedTables[tableName] {
		return ""
	}
	return fmt.Sprintf("SELECT * FROM %s ORDER BY created_at DESC LIMIT 50", tableName)
}
