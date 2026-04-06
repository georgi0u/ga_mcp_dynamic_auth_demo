package mcpservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adamgeorgiou/mcp_auth/server/internal/cryptox"
	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpclient"
	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestListConnectionToolDefinitions(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping", Description: "test tool"}, testToolHandler)

	httpServer := httptest.NewServer(mcp.NewSSEHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil))
	defer httpServer.Close()

	service := &Service{
		client: mcpclient.New("", 5*time.Second),
	}

	definitions, err := service.ListConnectionToolDefinitions(context.Background(), &store.Connection{
		ID:       "conn-123",
		Name:     "Example MCP",
		Endpoint: httpServer.URL,
		Status:   "connected",
	})
	if err != nil {
		t.Fatalf("ListConnectionToolDefinitions returned error: %v", err)
	}
	if len(definitions) != 1 {
		t.Fatalf("expected 1 tool definition, got %d", len(definitions))
	}

	definition := definitions[0]
	if definition.ConnectionID != "conn-123" {
		t.Fatalf("expected connection id conn-123, got %q", definition.ConnectionID)
	}
	if definition.ConnectionName != "Example MCP" {
		t.Fatalf("expected connection name Example MCP, got %q", definition.ConnectionName)
	}
	if definition.MCPName != "ping" {
		t.Fatalf("expected MCP tool name ping, got %q", definition.MCPName)
	}
	if definition.Description != "test tool" {
		t.Fatalf("expected description test tool, got %q", definition.Description)
	}
	if !strings.HasPrefix(definition.FunctionName, "mcp_") || !strings.HasSuffix(definition.FunctionName, "_ping") {
		t.Fatalf("expected generated function name for ping tool, got %q", definition.FunctionName)
	}
	if got := definition.Parameters["type"]; got != "object" {
		t.Fatalf("expected parameters type object, got %#v", got)
	}
}

func TestApplyServerDefinitionReplacesClientCredentials(t *testing.T) {
	t.Parallel()

	service := &Service{
		crypto: cryptox.New([]byte("0123456789abcdef0123456789abcdef")),
	}

	clientSecretEnc, err := service.crypto.EncryptString("old-secret")
	if err != nil {
		t.Fatalf("EncryptString returned error: %v", err)
	}

	server := &store.MCPServer{
		ClientID:                "old-client",
		ClientSecretEnc:         clientSecretEnc,
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	err = service.applyServerDefinition(server, mcpclient.ServerDefinition{
		ClientID:                 "new-client",
		TokenEndpointAuthMethod:  "none",
		ReplaceClientCredentials: true,
	})
	if err != nil {
		t.Fatalf("applyServerDefinition returned error: %v", err)
	}

	if server.ClientID != "new-client" {
		t.Fatalf("expected client_id new-client, got %q", server.ClientID)
	}
	if server.ClientSecretEnc != "" {
		t.Fatalf("expected client secret to be cleared, got %q", server.ClientSecretEnc)
	}
	if server.TokenEndpointAuthMethod != "none" {
		t.Fatalf("expected token endpoint auth method none, got %q", server.TokenEndpointAuthMethod)
	}
}

func testToolHandler(
	context.Context,
	*mcp.CallToolRequest,
	map[string]any,
) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{}, nil, nil
}
