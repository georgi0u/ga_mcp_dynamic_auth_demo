package mcpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAuthorizationServerMetadataURL(t *testing.T) {
	t.Parallel()

	root, err := authorizationServerMetadataURL("https://issuer.example")
	if err != nil {
		t.Fatalf("unexpected error for root issuer: %v", err)
	}
	if root != "https://issuer.example/.well-known/oauth-authorization-server" {
		t.Fatalf("unexpected root metadata URL: %s", root)
	}

	nested, err := authorizationServerMetadataURL("https://issuer.example/tenant-a")
	if err != nil {
		t.Fatalf("unexpected error for nested issuer: %v", err)
	}
	if nested != "https://issuer.example/.well-known/oauth-authorization-server/tenant-a" {
		t.Fatalf("unexpected nested metadata URL: %s", nested)
	}
}

func TestBuildAuthorizationURL(t *testing.T) {
	t.Parallel()

	raw, err := buildAuthorizationURL(
		"https://issuer.example/oauth2/authorize",
		"client-123",
		"http://localhost:8080/oauth/callback",
		"state-456",
		"verifier-789",
		"https://resource.example/mcp",
		[]string{"calendar.readonly", "openid"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}

	query := parsed.Query()
	if got := query.Get("client_id"); got != "client-123" {
		t.Fatalf("unexpected client_id: %s", got)
	}
	if got := query.Get("state"); got != "state-456" {
		t.Fatalf("unexpected state: %s", got)
	}
	if got := query.Get("resource"); got != "https://resource.example/mcp" {
		t.Fatalf("unexpected resource: %s", got)
	}
	if got := query.Get("scope"); got != "calendar.readonly openid" {
		t.Fatalf("unexpected scope: %s", got)
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("unexpected code_challenge_method: %s", got)
	}
	if got := query.Get("code_challenge"); got == "" {
		t.Fatalf("expected code_challenge to be set")
	}
}

func TestExtractResourceMetadataURL(t *testing.T) {
	t.Parallel()

	headers := []string{
		`Bearer realm="example", resource_metadata="https://resource.example/.well-known/oauth-protected-resource"`,
	}
	got := extractResourceMetadataURL(headers)
	want := "https://resource.example/.well-known/oauth-protected-resource"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestShouldFallbackToLegacySSE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "method not allowed", err: assertErr("sending \"initialize\": Method Not Allowed"), want: true},
		{name: "bad request", err: assertErr("sending \"initialize\": Bad Request"), want: true},
		{name: "not found", err: assertErr("sending \"initialize\": Not Found"), want: true},
		{name: "unauthorized", err: assertErr("sending \"initialize\": Unauthorized"), want: false},
		{name: "other", err: assertErr("boom"), want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldFallbackToLegacySSE(tc.err); got != tc.want {
				t.Fatalf("shouldFallbackToLegacySSE(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestListToolsFallsBackToLegacySSE(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping", Description: "test tool"}, testToolHandler)

	httpServer := httptest.NewServer(mcp.NewSSEHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil))
	defer httpServer.Close()

	manager := &Manager{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	tools, _, err := manager.ListTools(context.Background(), SessionDefinition{
		Name: "legacy-sse",
		Server: ServerDefinition{
			Endpoint: httpServer.URL,
		},
	})
	if err != nil {
		t.Fatalf("listTools returned error: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "ping" {
		t.Fatalf("expected tool named ping, got %q", tools[0].Name)
	}
}

func TestDynamicRegisterClientOmitsScope(t *testing.T) {
	t.Parallel()

	var captured clientRegistrationRequest
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-123","token_endpoint_auth_method":"none"}`))
	}))
	defer httpServer.Close()

	manager := &Manager{
		publicBaseURL: "http://localhost:8080",
		httpClient:    httpServer.Client(),
	}

	registration, err := manager.dynamicRegisterClient(context.Background(), ServerDefinition{
		RegistrationEndpoint: httpServer.URL,
	})
	if err != nil {
		t.Fatalf("dynamicRegisterClient returned error: %v", err)
	}
	if registration.ClientID != "client-123" {
		t.Fatalf("unexpected client ID %q", registration.ClientID)
	}
	if captured.Scope != "" {
		t.Fatalf("expected registration scope to be empty, got %q", captured.Scope)
	}
}

func testToolHandler(
	context.Context,
	*mcp.CallToolRequest,
	map[string]any,
) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{}, nil, nil
}

type assertErr string

func (e assertErr) Error() string {
	return string(e)
}
