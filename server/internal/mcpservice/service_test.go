package mcpservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func testToolHandler(
	context.Context,
	*mcp.CallToolRequest,
	map[string]any,
) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{}, nil, nil
}
