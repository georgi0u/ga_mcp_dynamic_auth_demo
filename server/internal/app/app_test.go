package app

import (
	"net/http/httptest"
	"testing"
)

func TestExtractBearerToken(
	t *testing.T,
) {
	t.Parallel()

	if got := extractBearerToken("Bearer token-123"); got != "token-123" {
		t.Fatalf("expected token-123, got %q", got)
	}
	if got := extractBearerToken("Basic nope"); got != "" {
		t.Fatalf("expected empty token, got %q", got)
	}
}

func TestIsWebsocketUpgrade(
	t *testing.T,
) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")

	if !isWebsocketUpgrade(req) {
		t.Fatalf("expected websocket upgrade to be detected")
	}
}
