package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (m *Client) ListTools(
	ctx context.Context,
	session SessionDefinition,
) ([]*mcp.Tool, *TokenSet, error) {
	var tools []*mcp.Tool
	refreshedTokens, err := m.withSession(
		ctx,
		session,
		func(session *mcp.ClientSession) error {
			result, err := session.ListTools(ctx, &mcp.ListToolsParams{})
			if err != nil {
				return err
			}
			tools = result.Tools
			return nil
		},
	)
	if err != nil {
		return nil, refreshedTokens, err
	}
	return tools, refreshedTokens, nil
}

func (m *Client) CallTool(
	ctx context.Context,
	session SessionDefinition,
	toolName string,
	args map[string]any,
) (string, *TokenSet, error) {
	var callResult *mcp.CallToolResult
	refreshedTokens, err := m.withSession(
		ctx,
		session,
		func(session *mcp.ClientSession) error {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      toolName,
				Arguments: args,
			})
			if err != nil {
				return err
			}
			callResult = result
			return nil
		},
	)
	if err != nil {
		return "", refreshedTokens, err
	}

	payload := map[string]any{"is_error": callResult.IsError}
	if callResult.StructuredContent != nil {
		payload["structured"] = callResult.StructuredContent
	}

	content := make([]string, 0, len(callResult.Content))
	for _, item := range callResult.Content {
		switch typed := item.(type) {
		case *mcp.TextContent:
			content = append(content, typed.Text)
		default:
			raw, _ := json.Marshal(typed)
			content = append(content, string(raw))
		}
	}
	if len(content) > 0 {
		payload["content"] = content
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", refreshedTokens, fmt.Errorf("marshal tool payload: %w", err)
	}
	return string(raw), refreshedTokens, nil
}
