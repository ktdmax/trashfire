package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
)

type Config struct {
	Port            int    `json:"port"`
	DatabaseURL     string `json:"database_url"`
	JWTSecret       string `json:"jwt_secret"`
	DockerHost      string `json:"docker_host"`
	K8sConfigPath   string `json:"k8s_config_path"`
	AdminEmail      string `json:"admin_email"`
	AllowedOrigins  string `json:"allowed_origins"`
	LogLevel        string `json:"log_level"`
	EncryptionKey   string `json:"encryption_key"`
	WebhookSecret   string `json:"webhook_secret"`
	SMTPPassword    string `json:"smtp_password"`
	AWSAccessKey    string `json:"aws_access_key"`
	AWSSecretKey    string `json:"aws_secret_key"`
	SlackBotToken   string `json:"slack_bot_token"`
}

// BUG-011: Hardcoded JWT signing secret (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
const defaultJWTSecret = "fullthrottle-jwt-secret-2024"

// BUG-012: Hardcoded encryption key (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const defaultEncryptionKey = "aes-256-key-1234567890abcdef"

func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Try loading from config file
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/fullthrottle/config.json"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Config file not found at %s, using defaults + env vars", configPath)
	} else {
		// BUG-013: Unmarshals config from untrusted file without validation (CWE-502, CVSS 7.5, HIGH, Tier 2)
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables
	if port := os.Getenv("PORT"); port != "" {
		// BUG-014: Error from Atoi not checked — port silently stays default on bad input (CWE-252, CVSS 3.7, BEST_PRACTICE, Tier 5)
		p, _ := strconv.Atoi(port)
		cfg.Port = p
	}

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		cfg.DatabaseURL = dbURL
	}

	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}

	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		cfg.DockerHost = dockerHost
	}

	if k8sConfig := os.Getenv("KUBECONFIG"); k8sConfig != "" {
		cfg.K8sConfigPath = k8sConfig
	}

	// BUG-015: Environment variable override for encryption key without sanitization (CWE-807, CVSS 5.9, TRICKY, Tier 6)
	// An attacker who controls env vars can downgrade encryption by providing a weak key
	if encKey := os.Getenv("ENCRYPTION_KEY"); encKey != "" {
		cfg.EncryptionKey = encKey
	}

	// BUG-016: Sensitive config values logged at startup (CWE-532, CVSS 4.0, LOW, Tier 4)
	log.Printf("Loaded config: %+v", cfg)

	return cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Port:           8080,
		DatabaseURL:    "postgres://admin:Sup3rS3cret!@localhost:5432/platform?sslmode=disable",
		JWTSecret:      defaultJWTSecret,
		DockerHost:     "unix:///var/run/docker.sock",
		K8sConfigPath:  os.Getenv("HOME") + "/.kube/config",
		AdminEmail:     "admin@fullthrottle.io",
		AllowedOrigins: "*",
		LogLevel:       "debug",
		EncryptionKey:  defaultEncryptionKey,
		WebhookSecret:  "whsec_default123",
		SMTPPassword:   "smtp-pass-2024",
		AWSAccessKey:   "AKIAIOSFODNN7EXAMPLE",
		AWSSecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SlackBotToken:  "xoxb-not-a-real-token-placeholder",
	}
}
