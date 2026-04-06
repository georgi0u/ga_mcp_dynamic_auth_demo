package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultAddr             = ":8080"
	defaultPublicBaseURL    = "http://localhost:8080"
	defaultClientAppURL     = "http://localhost:3000"
	defaultDatabaseURL      = "postgres://postgres:postgres@localhost:5432/mcp_auth?sslmode=disable"
	defaultOpenAIModel      = "gpt-5.2"
	defaultSessionTTL       = 24 * time.Hour
	defaultRequestTimeout   = 60 * time.Second
	defaultBootstrapEmail   = "demo@example.com"
	defaultBootstrapPass    = "demo-password"
	defaultDevelopmentKey32 = "0123456789abcdefghijklmnopqrstuv"
)

type Config struct {
	Addr                string
	PublicBaseURL       string
	ClientAppURL        string
	AllowedOrigins      []string
	DatabaseURL         string
	ResetDBOnFirstStart bool
	OpenAIAPIKey        string
	OpenAIModel         string
	SessionTTL          time.Duration
	RequestTimeout      time.Duration
	BootstrapEmail      string
	BootstrapPassword   string
	EncryptionKey       []byte
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                getenv("APP_ADDR", defaultAddr),
		PublicBaseURL:       getenv("APP_PUBLIC_BASE_URL", defaultPublicBaseURL),
		ClientAppURL:        getenv("CLIENT_APP_URL", defaultClientAppURL),
		DatabaseURL:         getenv("DATABASE_URL", defaultDatabaseURL),
		ResetDBOnFirstStart: parseBool("RESET_DATABASE_ON_FIRST_START", false),
		OpenAIAPIKey:        strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIModel:         getenv("OPENAI_MODEL", defaultOpenAIModel),
		SessionTTL:          parseDuration("SESSION_TTL", defaultSessionTTL),
		RequestTimeout:      parseDuration("REQUEST_TIMEOUT", defaultRequestTimeout),
		BootstrapEmail:      getenv("BOOTSTRAP_EMAIL", defaultBootstrapEmail),
		BootstrapPassword:   getenv("BOOTSTRAP_PASSWORD", defaultBootstrapPass),
	}

	if _, err := url.Parse(cfg.PublicBaseURL); err != nil {
		return Config{}, fmt.Errorf("parse APP_PUBLIC_BASE_URL: %w", err)
	}
	if _, err := url.Parse(cfg.ClientAppURL); err != nil {
		return Config{}, fmt.Errorf("parse CLIENT_APP_URL: %w", err)
	}

	cfg.AllowedOrigins = parseOrigins(getenv("ALLOWED_ORIGINS", cfg.ClientAppURL))

	key, err := parseKey(getenv("APP_ENCRYPTION_KEY", defaultDevelopmentKey32))
	if err != nil {
		return Config{}, err
	}
	cfg.EncryptionKey = key

	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseDuration(
	key string,
	fallback time.Duration,
) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseBool(
	key string,
	fallback bool,
) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := map[string]struct{}{}
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins
}

func parseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("APP_ENCRYPTION_KEY is empty")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("APP_ENCRYPTION_KEY must be 32 raw bytes or base64-encoded 32 bytes")
}
